// Structures from pointer use and from a listing selection (feature
// auto-struct, docs/types.md "Structures from pointer use"): Ghidra's Auto
// Create Structure and Auto Fill in Structure on a decompiler variable or a
// struct field (chained structures), and Create Structure on a listing
// selection. The daemon composes the structure (TypeService.AutoStructure,
// which asserts nothing); this dialog previews its fields and, with feature
// auto-struct-edit, edits them before Apply: a field renamed, retyped (any
// C type; its size follows), removed (filler) or added in filler. Edits go
// back to the daemon (AutoStructureRequest.edits), which recomposes and
// says per field what doesn't fit; Apply hands the response back for one
// AppendAssertions (one undo step).

import { AutoStructureFieldEditSchema, AutoStructureFieldSource, type AutoStructureField, type AutoStructureRequest, type AutoStructureResponse, type Revkit } from "@revkit/api";
import { create } from "@bufbuild/protobuf";
import { errText, hex as bare } from "../data/format";
import { h, overlayRoot, prefs } from "./dom";
import type { Suggestion } from "./dialogs";

export interface StructurePreviewOptions {
  rk: Revkit;
  /** "Auto create structure for param_1 in walk". */
  title: string;
  /** The request (its name and call depth are the dialog's). */
  request: AutoStructureRequest;
  /** The name can be edited (a new structure; Auto Fill in keeps the struct's). */
  named: boolean;
  /** Offer the call depth (a variable's structure). */
  depth: boolean;
  /** Fields can be edited (feature auto-struct-edit). */
  editable?: boolean;
  /** Type completion for the type cells (the Set type chooser's). */
  suggest?: (text: string) => Promise<Suggestion[]>;
}

export interface StructurePreviewResult {
  made: AutoStructureResponse;
  /** "Open in Types editor after apply" was checked. */
  openTypes: boolean;
}

const hex = (v: bigint) => `0x${bare(v)}`;
const OPEN_TYPES = "rk.autostruct.openTypes";

const SOURCE: Record<number, string> = {
  [AutoStructureFieldSource.ACCESS]: "new",
  [AutoStructureFieldSource.EXISTING]: "kept",
  [AutoStructureFieldSource.DATA]: "data",
};

/** One field's edits in the dialog, by offset (what AutoStructureRequest.edits carries). */
interface Edit {
  name?: string;
  type?: string;
  remove?: boolean;
  add?: boolean;
  /** What a removed field was (to show it, and restore it). */
  was?: { name: string; type: string; size: bigint };
}

const C_NAME = /^[A-Za-z_]\w*$/;
let datalists = 0;

/** Previews the structure; resolves to the response to apply, or null when cancelled. */
export function previewStructure(o: StructurePreviewOptions): Promise<StructurePreviewResult | null> {
  return new Promise((resolve) => {
    const restore = document.activeElement as HTMLElement | null;
    let current: AutoStructureResponse | null = null;
    let asked = 0;
    const edits = new Map<bigint, Edit>();
    const editable = o.editable ?? false;
    const name = h("input", { class: "ask-input as-name", spellcheck: "false", autocomplete: "off", "aria-label": "Structure name", "data-testid": "as-name", placeholder: "astruct" });
    name.value = o.request.name;
    const depth = h(
      "select",
      { class: "filter select", "aria-label": "Call depth", "data-testid": "as-depth", title: "How many calls deep to follow the pointer into the functions it is passed to" },
      ...[0, 1, 2, 3, 4].map((d) => h("option", { value: String(d) }, d === 0 ? "this function only" : `${d} call${d > 1 ? "s" : ""} deep`)),
    );
    depth.value = String(o.request.callDepth ?? 1);
    const summary = h("div", { class: "dim as-summary", "data-testid": "as-summary" }, "Composing…");
    const rows = h("tbody", {});
    const listId = `as-types-${++datalists}`;
    const types = h("datalist", { id: listId });
    const table = h(
      "table",
      { class: "as-fields" + (editable ? " editable" : ""), "data-testid": "as-fields" },
      h("thead", {}, h("tr", {}, h("th", {}, "Offset"), h("th", {}, "Size"), h("th", {}, "Type"), h("th", {}, "Name"), h("th", {}, ""), editable ? h("th", {}, "") : null)),
      rows,
    );
    const err = h("div", { class: "ask-error", "data-testid": "as-error" });
    const openBox = h("input", { type: "checkbox", "data-testid": "as-open-types" }) as HTMLInputElement;
    openBox.checked = prefs.get(OPEN_TYPES) === "1";
    openBox.addEventListener("change", () => prefs.set(OPEN_TYPES, openBox.checked ? "1" : "0"));
    const apply = h("button", { class: "btn primary", "data-testid": "as-apply", disabled: true, onclick: () => take() }, "Apply");
    const cancel = h("button", { class: "btn", "data-testid": "as-cancel", onclick: () => done(null) }, "Cancel");
    const box = h(
      "div",
      { class: "modal auto-struct", tabindex: "-1", role: "dialog", "aria-modal": "true", "aria-label": o.title, "data-testid": "auto-struct" },
      h("div", { class: "modal-title" }, o.title),
      h("div", { class: "ask-row" }, o.named ? h("label", { class: "ask-label dim" }, "Name", name) : null, o.depth ? depth : null),
      summary,
      h("div", { class: "as-scroll" }, table, types),
      err,
      h(
        "div",
        { class: "as-buttons" },
        h("label", { class: "ask-check dim small", title: "After Apply, open the structure in the Types view for bigger edits" }, openBox, "Open in Types editor after apply"),
        h("span", { class: "spacer" }),
        cancel,
        apply,
      ),
      h(
        "div",
        { class: "modal-hint" },
        editable
          ? "Edit a field's type or name (Enter or Tab commits the cell) · × removes it · + adds one in filler · Ctrl+Enter applies (one undo step) · Esc cancels"
          : "Enter to apply (one undo step) · Esc to cancel",
      ),
    );
    const backdrop = h("div", { class: "backdrop" }, box);

    /** The edits as the request carries them (an added field without a type yet stays local). */
    const requestEdits = () =>
      [...edits].flatMap(([offset, e]) => {
        if (e.add && !e.type?.trim()) return [];
        if (!e.remove && !e.add && e.name === undefined && e.type === undefined) return [];
        return [
          create(AutoStructureFieldEditSchema, {
            offset,
            name: e.name?.trim() ?? "",
            type: e.type?.trim() ? { case: "typeC", value: e.type.trim() } : { case: undefined },
            remove: !!e.remove,
            add: !!e.add,
          }),
        ];
      });

    // --- the table ---
    const cell = (kind: "type" | "name", offset: bigint, value: string, problem: boolean) => {
      const input = h("input", {
        class: "as-cell mono" + (problem ? " problem" : ""),
        spellcheck: "false",
        autocomplete: "off",
        "aria-label": `${kind === "type" ? "Type" : "Name"} of the field at ${hex(offset)}`,
        "data-testid": `as-field-${kind}`,
        "data-offset": hex(offset),
        list: kind === "type" && o.suggest ? listId : undefined,
      }) as HTMLInputElement;
      input.value = value;
      input.dataset.committed = value;
      if (kind === "type" && o.suggest) input.addEventListener("input", () => void fillTypes(input.value));
      // A cell commits on Enter, Tab or leaving it (change).
      input.addEventListener("change", () => commit(input, kind, offset));
      return input;
    };
    const commit = (input: HTMLInputElement, kind: "type" | "name", offset: bigint) => {
      const v = input.value.trim();
      if (v === input.dataset.committed) return;
      if (kind === "name" && v && !C_NAME.test(v)) {
        input.classList.add("problem");
        err.textContent = `${v} is not a C name (letters, digits, _)`;
        return;
      }
      if (kind === "name" && v) {
        const taken = current?.fields.some((f) => f.offset !== offset && f.name === v) || [...edits].some(([k, e]) => k !== offset && e.name === v && !e.remove);
        if (taken) {
          input.classList.add("problem");
          err.textContent = `another field is named ${v}`;
          return;
        }
      }
      input.classList.remove("problem");
      err.textContent = "";
      input.dataset.committed = v;
      const e = edits.get(offset) ?? {};
      if (kind === "name") e.name = v || undefined;
      else e.type = v || undefined;
      edits.set(offset, e);
      schedule(150);
    };
    let typeSeq = 0;
    const fillTypes = async (text: string) => {
      if (!o.suggest) return;
      const n = ++typeSeq;
      const list = await o.suggest(text).catch(() => [] as Suggestion[]);
      if (n !== typeSeq) return;
      types.replaceChildren(...list.slice(0, 40).map((s) => h("option", { value: s.insert }, s.detail ? `${s.label} · ${s.detail}` : s.label)));
    };

    const errorsAt = () => {
      const m = new Map<bigint, string[]>();
      for (const e of current?.fieldErrors ?? []) m.set(e.offset, [...(m.get(e.offset) ?? []), e.message]);
      return m;
    };
    const fieldRow = (f: AutoStructureField, problems: string[] | undefined) => {
      const e = edits.get(f.offset);
      return h(
        "tr",
        { class: `as-field as-${SOURCE[f.source] ?? "x"}` + (f.edited ? " as-edited" : "") + (problems ? " as-problem" : ""), "data-testid": "as-field", "data-offset": hex(f.offset) },
        h("td", { class: "mono" }, hex(f.offset)),
        h("td", { class: "mono" }, String(f.size)),
        editable ? h("td", {}, cell("type", f.offset, e?.type ?? f.typeDisplay, !!problems)) : h("td", { class: "mono" }, f.typeDisplay + (f.truncated ? " (split)" : "")),
        editable ? h("td", {}, cell("name", f.offset, e?.name ?? f.name, false)) : h("td", { class: "mono" }, f.name),
        h("td", { class: "dim", title: f.accesses ? `${f.accesses} load${f.accesses === 1 ? "" : "s"} or stores` : "" }, f.edited ? "edited" : (SOURCE[f.source] ?? "")),
        editable
          ? h("td", { class: "row-actions" }, h("button", { class: "icon", type: "button", tabindex: "-1", title: "Remove the field (its bytes become filler)", "aria-label": `Remove ${f.name}`, "data-testid": "as-field-remove", onclick: () => removeField(f) }, "×"))
          : null,
      );
    };
    const fillerRow = (offset: bigint, size: bigint) =>
      h(
        "tr",
        { class: "as-filler dim", "data-testid": "as-filler", "data-offset": hex(offset) },
        h("td", { class: "mono" }, hex(offset)),
        h("td", { class: "mono" }, String(size)),
        h("td", { class: "mono", colspan: "3" }, "undefined (filler)"),
        editable
          ? h("td", { class: "row-actions" }, h("button", { class: "icon", type: "button", tabindex: "-1", title: "Add a field here", "aria-label": `Add a field at ${hex(offset)}`, "data-testid": "as-field-add", onclick: () => addField(offset) }, "+"))
          : null,
      );
    const addRow = (offset: bigint, e: Edit, problems: string[] | undefined) => {
      const tr = h(
        "tr",
        { class: "as-field as-added" + (problems ? " as-problem" : ""), "data-testid": "as-field", "data-offset": hex(offset) },
        h("td", { class: "mono" }, hex(offset)),
        h("td", { class: "mono dim" }, "?"),
        h("td", {}, cell("type", offset, e.type ?? "", !!problems)),
        h("td", {}, cell("name", offset, e.name ?? "", false)),
        h("td", { class: "dim" }, "added"),
        h("td", { class: "row-actions" }, h("button", { class: "icon", type: "button", tabindex: "-1", title: "Drop this new field", "aria-label": `Drop the new field at ${hex(offset)}`, "data-testid": "as-field-remove", onclick: () => { edits.delete(offset); schedule(0); } }, "×")),
      );
      tr.querySelector<HTMLInputElement>("[data-testid=as-field-type]")!.placeholder = "int, char[8], struct x *";
      return tr;
    };
    const removedRow = (offset: bigint, e: Edit) =>
      h(
        "tr",
        { class: "as-removed dim", "data-testid": "as-removed", "data-offset": hex(offset) },
        h("td", { class: "mono" }, hex(offset)),
        h("td", { class: "mono" }, String(e.was?.size ?? "")),
        h("td", { class: "mono" }, e.was?.type ?? ""),
        h("td", { class: "mono" }, e.was?.name ?? ""),
        h("td", {}, "removed"),
        h("td", { class: "row-actions" }, h("button", { class: "icon", type: "button", tabindex: "-1", title: "Keep the field", "aria-label": `Restore ${e.was?.name ?? "the field"}`, "data-testid": "as-field-restore", onclick: () => { edits.delete(offset); schedule(0); } }, "↶")),
      );
    const problemRow = (messages: string[], offset: bigint) =>
      h("tr", { class: "as-field-error", "data-testid": "as-field-error", "data-offset": hex(offset) }, h("td", {}), h("td", { colspan: "5", class: "error" }, messages.join("; ")));

    const removeField = (f: AutoStructureField) => {
      edits.set(f.offset, { remove: true, was: { name: f.name, type: f.typeDisplay, size: f.size } });
      schedule(0);
    };
    const addField = (offset: bigint) => {
      edits.set(offset, { add: true, type: "", name: "" });
      if (current) paint(current);
      rows.querySelector<HTMLInputElement>(`[data-testid=as-field-type][data-offset='${hex(offset)}']`)?.focus();
    };

    const paint = (r: AutoStructureResponse) => {
      // Keep the focus in the cell being edited across the repaint.
      const focused = document.activeElement as HTMLInputElement | null;
      // (the whole selection: text selected to type over stays selected).
      const keep = focused?.classList.contains("as-cell")
        ? { id: focused.dataset.testid, at: focused.dataset.offset, value: focused.value, from: focused.selectionStart, to: focused.selectionEnd, dir: focused.selectionDirection ?? undefined }
        : null;
      const added = r.fields.filter((f) => f.source === AutoStructureFieldSource.ACCESS || f.source === AutoStructureFieldSource.DATA).length;
      const reads = r.functions.length;
      const problems = errorsAt();
      summary.textContent =
        `struct ${r.name || "(anonymous)"}: ${hex(r.size)} bytes, ${r.fields.length} field${r.fields.length === 1 ? "" : "s"}` +
        (r.existingHash ? `, ${added} new` : "") +
        (reads ? ` · from ${r.accesses.length} access${r.accesses.length === 1 ? "" : "es"} in ${reads} function${reads === 1 ? "" : "s"}` : "") +
        (r.outerNamedKey ? ` · ${r.outerNamedKey}'s field will point to it` : "") +
        (r.unchanged ? " · nothing would change" : "") +
        (r.notes.length ? ` · ${r.notes.join("; ")}` : "");
      // The fields, filler between them, local additions and removals, by offset.
      type Item = { at: bigint; el: HTMLElement[] };
      const items: Item[] = [];
      let pos = 0n;
      const localAdds = [...edits].filter(([at, e]) => e.add && !r.fields.some((f) => f.offset === at && f.edited));
      const removed = [...edits].filter(([, e]) => e.remove);
      const fillers: [bigint, bigint][] = [];
      for (const f of r.fields) {
        if (f.offset > pos) fillers.push([pos, f.offset - pos]);
        const p = problems.get(f.offset);
        items.push({ at: f.offset, el: [fieldRow(f, p), ...(p ? [problemRow(p, f.offset)] : [])] });
        pos = f.offset + f.size > pos ? f.offset + f.size : pos;
      }
      if (r.size > pos) fillers.push([pos, r.size - pos]);
      for (const [at, size] of fillers) {
        // A filler run that starts with a local addition shows it instead.
        const inside = localAdds.filter(([a]) => a >= at && a < at + size).map(([a]) => a);
        if (!inside.includes(at)) items.push({ at, el: [fillerRow(at, (inside[0] ?? at + size) - at)] });
      }
      for (const [at, e] of localAdds) {
        const p = problems.get(at);
        items.push({ at, el: [addRow(at, e, p), ...(p ? [problemRow(p, at)] : [])] });
      }
      for (const [at, e] of removed) {
        const p = problems.get(at);
        items.push({ at, el: [removedRow(at, e), ...(p ? [problemRow(p, at)] : [])] });
      }
      // Errors for offsets no row shows (an edit at a bad offset).
      for (const [at, p] of problems) if (!items.some((i) => i.at === at)) items.push({ at, el: [problemRow(p, at)] });
      items.sort((a, b) => (a.at < b.at ? -1 : a.at > b.at ? 1 : 0));
      rows.replaceChildren(...items.flatMap((i) => i.el));
      if (keep) {
        const again = rows.querySelector<HTMLInputElement>(`[data-testid=${keep.id}][data-offset='${keep.at}']`);
        if (again) {
          again.value = keep.value;
          again.focus({ preventScroll: true });
          if (keep.from !== null && keep.to !== null) again.setSelectionRange(keep.from, keep.to, keep.dir);
        }
      }
    };

    const refresh = async () => {
      timer = undefined;
      const n = ++asked;
      const req = {
        ...o.request,
        name: o.named ? name.value.trim() : o.request.name,
        callDepth: o.depth ? Number(depth.value) : o.request.callDepth,
        edits: editable ? requestEdits() : [],
      };
      apply.disabled = true;
      box.classList.add("busy");
      try {
        const r = await o.rk.types.autoStructure(req);
        if (n !== asked) return;
        current = r;
        // The daemon's choice of name ("astruct_2"), until one is typed.
        if (o.named && !nameEdited && r.name) name.value = r.name;
        err.textContent = r.fieldErrors.length ? `${r.fieldErrors.length} edit${r.fieldErrors.length === 1 ? "" : "s"} can't be made (below): fix or drop ${r.fieldErrors.length === 1 ? "it" : "them"} to apply` : "";
        paint(r);
        apply.disabled = r.nodes.length === 0 || r.unchanged || r.fieldErrors.length > 0;
      } catch (e) {
        if (n !== asked) return;
        current = null;
        err.textContent = errText(e);
      } finally {
        if (n === asked) box.classList.remove("busy");
      }
    };
    let timer: ReturnType<typeof setTimeout> | undefined;
    const schedule = (ms: number) => {
      clearTimeout(timer);
      apply.disabled = true;
      timer = setTimeout(() => void refresh(), ms);
    };
    let nameEdited = false;
    name.addEventListener("input", () => {
      nameEdited = true;
      schedule(250);
    });
    depth.addEventListener("change", () => schedule(0));

    const done = (v: StructurePreviewResult | null) => {
      clearTimeout(timer);
      backdrop.remove();
      restore?.focus({ preventScroll: true });
      resolve(v);
    };
    /** Applies once the cell being typed in (if any) is committed and the answer to it is in. */
    const take = async () => {
      const active = document.activeElement as HTMLInputElement | null;
      if (active?.classList.contains("as-cell") && active.value.trim() !== active.dataset.committed) active.dispatchEvent(new Event("change"));
      if (timer !== undefined) {
        clearTimeout(timer);
        await refresh();
      }
      if (current && !apply.disabled) done({ made: current, openTypes: openBox.checked });
    };
    box.addEventListener("keydown", (e) => {
      e.stopPropagation();
      const t = e.target as HTMLElement;
      if (e.key === "Escape") done(null);
      else if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
        e.preventDefault();
        void take();
      } else if (e.key === "Enter" && t.classList.contains("as-cell")) {
        // Enter in a cell commits it (not Apply).
        e.preventDefault();
        t.dispatchEvent(new Event("change"));
      } else if (e.key === "Enter" && t.tagName !== "BUTTON" && t.tagName !== "SELECT") {
        e.preventDefault();
        void take();
      }
    });
    backdrop.addEventListener("mousedown", (e) => {
      if (e.target === backdrop) done(null);
    });
    overlayRoot().append(backdrop);
    (o.named ? name : box).focus();
    if (o.named) name.select();
    void refresh();
  });
}
