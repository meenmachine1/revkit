// Cross-reference list: references to an address (GetXrefs, direction TO),
// navigable with the keyboard. Virtualized and fetched a page at a time as
// it scrolls (one revision), so a function with 50,000 callers opens at
// once.

import { XrefDirection, XrefKind, type Revkit, type Xref } from "@revkit/api";
import { errText, fmtAddr, provBadge } from "../data/format";
import { h, overlayRoot } from "./dom";
import { VirtualRows } from "./vlist";

export const KIND: Record<number, string> = {
  [XrefKind.CALL]: "call",
  [XrefKind.JUMP]: "jump",
  [XrefKind.CONDITIONAL_JUMP]: "cjump",
  [XrefKind.INDIRECT_CALL]: "icall",
  [XrefKind.INDIRECT_JUMP]: "ijump",
  [XrefKind.DATA_READ]: "read",
  [XrefKind.DATA_WRITE]: "write",
  [XrefKind.DATA_POINTER]: "ptr",
  [XrefKind.THUNK]: "thunk",
  [XrefKind.FALLTHROUGH]: "fall",
};

/** One reference to a library's export from a program that imports it (ListLibraryImporters). */
export interface ImporterRef {
  programId: string;
  programName: string;
  /** Where in the importer: the referencing instruction, else the import's thunk or slot. */
  address: bigint;
  /** "call", "read", ... or "import" (the thunk itself, nothing references it). */
  kind: string;
  /** Its function in the importer, if any. */
  fn: string;
}

const ROW_H = 30;
const PAGE = 2000;

/** The references to `address` in a dialog: virtualized and paged, so tens of thousands open at once. */
export async function showXrefs(
  rk: Revkit,
  programId: string,
  address: bigint,
  name: string,
  addrWidth: number,
  go: (a: bigint) => void,
  /** An import thunk: where it goes ("libc.so.6!strlen", feature program-libraries) and opening it there. */
  external?: { text: string; open: () => void },
  /** A library's export: the programs that import it and their references (feature library-importers). */
  importers?: { load: () => Promise<ImporterRef[]>; open: (programId: string, address: bigint) => void },
) {
  const restore = document.activeElement as HTMLElement | null;
  const list = h("div", { class: "palette-list xrefs-list", role: "listbox", "aria-label": `References to ${name}`, "data-testid": "xrefs-list" });
  const title = h("div", { class: "modal-title" }, `References to ${name}`);
  const ext = external
    ? h(
        "div",
        { class: "xrefs-external" },
        h("span", { class: "dim" }, "Imported: goes to"),
        h("button", { class: "link mono", type: "button", "data-testid": "xrefs-external", title: "Open the library program at the function", onclick: () => { close(false); external.open(); } }, external.text),
      )
    : null;
  // From the programs that import it (a library's export), filled in once loaded.
  const imp = importers ? h("div", { class: "xrefs-importers", hidden: true, "data-testid": "xrefs-importers" }) : null;
  const box = h("div", { class: "modal palette xrefs", role: "dialog", "aria-modal": "true", "aria-label": `References to ${name}`, tabindex: "-1", "data-testid": "xrefs" }, title, ext, imp, list, h("div", { class: "modal-hint" }, "↑↓ PgUp PgDn select · Enter go · Esc close"));
  const backdrop = h("div", { class: "backdrop top" }, box);
  const items: Xref[] = [];
  let total = 0;
  let token = "";
  let revision = 0n;
  let fetching = false;
  let failed = "";
  let active = 0;
  const close = (focus = true) => {
    backdrop.remove();
    if (focus) restore?.focus({ preventScroll: true });
  };
  const accept = () => {
    const x = items[active];
    if (!x?.fromAddress) return;
    close(false);
    go(x.fromAddress.offset);
  };
  const fetchMore = async () => {
    if (fetching || (items.length && !token)) return;
    fetching = true;
    try {
      const r = await rk.queries.getXrefs({
        programId,
        location: { case: "address", value: { offset: address } },
        direction: XrefDirection.TO,
        page: { pageSize: PAGE, pageToken: token },
        read: { revision },
      });
      revision = r.snapshot?.revision ?? revision;
      items.push(...r.xrefs);
      token = r.page?.nextPageToken ?? "";
      total = r.page && r.page.totalCount > 0n ? Number(r.page.totalCount) : token ? items.length + 1 : items.length;
      title.textContent = `References to ${name} (${total.toLocaleString()})`;
    } catch (e) {
      failed = errText(e);
    } finally {
      fetching = false;
    }
    rows.count = Math.max(1, total);
  };
  const rows = new VirtualRows(
    list,
    ROW_H,
    (i) => {
      const x = items[i];
      if (failed && !items.length) return h("div", { class: "palette-empty error", role: "option", "aria-disabled": "true" }, failed);
      if (!total) return h("div", { class: "palette-empty dim", role: "option", "aria-disabled": "true" }, fetching || !revision ? "Loading…" : "No references");
      if (!x) return h("div", { class: "palette-item loading dim", role: "option" }, "…");
      return h(
        "div",
        { class: "palette-item" + (i === active ? " active" : ""), "data-i": i, role: "option", "aria-selected": String(i === active) },
        h("span", { class: "badge b-xref" }, KIND[x.kind] ?? "ref"),
        h("span", { class: "pi-label mono" }, fmtAddr(x.fromAddress?.offset ?? 0n, addrWidth)),
        h("span", { class: "pi-detail" }, x.fromFunctionName || "(no function)"),
        // A user's reference (feature user-references): who added it, and whether it is primary.
        x.origin?.source.case === "asserted" ? h("span", { class: "badge b-user", "data-testid": "xref-source" }, `${provBadge(x.origin.source.value.provenance)}${x.primary ? " · primary" : ""}`) : null,
      );
    },
    (_first, last) => {
      if (last > items.length && token && !fetching) void fetchMore();
    },
  );
  const move = (i: number) => {
    active = Math.max(0, Math.min(total - 1, i));
    rows.reveal(active);
  };
  box.addEventListener("keydown", (e) => {
    e.stopPropagation();
    const page = Math.max(1, Math.floor(list.clientHeight / ROW_H) - 1);
    if (e.key === "Escape") close();
    else if (e.key === "ArrowDown") move(active + 1);
    else if (e.key === "ArrowUp") move(active - 1);
    else if (e.key === "PageDown") move(active + page);
    else if (e.key === "PageUp") move(active - page);
    else if (e.key === "Home") move(0);
    else if (e.key === "End") move(total - 1);
    else if (e.key === "Enter") accept();
    else return;
    e.preventDefault();
  });
  list.addEventListener("mousedown", (e) => {
    const el = (e.target as HTMLElement).closest<HTMLElement>("[data-i]");
    if (!el) return;
    e.preventDefault();
    active = Number(el.dataset.i);
    accept();
  });
  backdrop.addEventListener("mousedown", (e) => {
    if (e.target === backdrop) close();
  });
  overlayRoot().append(backdrop);
  box.focus();
  rows.count = 1;
  if (importers && imp)
    void importers.load().then(
      (refs) => {
        if (!refs.length) return;
        const shown = refs.slice(0, 200);
        imp.replaceChildren(
          h("div", { class: "dim" }, `From programs that import it (${refs.length.toLocaleString()}${refs.length > shown.length ? `, ${shown.length} shown` : ""})`),
          ...shown.map((r) =>
            h(
              "button",
              {
                class: "link mono xrefs-importer",
                type: "button",
                "data-testid": "xrefs-importer",
                "data-program": r.programId,
                title: `Open ${r.programName} at 0x${r.address.toString(16)}`,
                onclick: () => { close(false); importers.open(r.programId, r.address); },
              },
              h("span", { class: "badge b-xref" }, r.kind),
              ` ${r.programName}!${r.fn || `0x${r.address.toString(16)}`}`,
            ),
          ),
        );
        imp.hidden = false;
      },
      () => {},
    );
  await fetchMore();
}
