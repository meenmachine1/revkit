// Import header…: a C header (pasted, uploaded, or a file on the daemon's
// host) parsed by the daemon (TypeService.ParseC, feature "parse-c") for
// the program's target, with include folders, -D/-U defines and the target
// shown and changeable. Parse shows a preview: each type the header
// declares is new, replaces the program's definition of its name (both C
// definitions side by side) or is identical (skipped), with a policy per
// row (import, replace, skip, rename); the diagnostics, each showing its
// line; #define constants as one enum per file; and, when asked, the
// functions its prototypes would retype, by name. Import defines the
// chosen types and binds their names in one AppendAssertions with
// provenance import:header (the file as its version, a session of its
// own): one revision, one undo step, live in every tab and for
// collaborators. docs/ui.md ("Types"), docs/cparse.md.
//
// Import archive… is the same dialog for a type archive (a header plus its
// JSON sidecar, feature "type-archive"): parsed for the sidecar's data
// model and checked against its hashes, previewed the same way, imported
// with provenance import:archive (the archive's origin as its version) and
// filed under the archive's categories. docs/types.md ("Type archives").

import { ParseCSeverity, ProvenanceKind, ProvenanceSchema, Role, SymbolKind, headerImportPlan, parsedStatus, type ParseCDiagnostic, type ParseCNamedType, type ParseCResponse, type Revkit } from "@revkit/api";
import { create } from "@bufbuild/protobuf";
import { CLIENT_NAME, SESSION, session as auth } from "../api/client";
import { Edits } from "../data/edits";
import { errText } from "../data/format";
import { toast } from "./dialogs";
import { h, overlayRoot, prefs } from "./dom";
import { pickFile, pickFiles } from "./filepick";
import { browseHost } from "./hostfiles";

export interface HeaderImportHost {
  rk: Revkit;
  programId: string;
  edits: Edits;
  /** Waits until this tab has seen a revision. */
  settle: (revision: bigint) => Promise<void>;
  /** The import landed (the types view shows it). */
  imported?: (keys: string[]) => void;
  /** A type archive (header and sidecar) rather than a header (feature "type-archive"). */
  archive?: boolean;
}

/** The targets ParseC knows by name (docs/cparse.md, "Targets and layout"). */
export const PROFILES = [
  "x86_64-linux-gnu", "aarch64-linux-gnu", "riscv64-linux-gnu", "x86_64-w64-mingw32", "x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc",
  "i386-linux-gnu", "i686-w64-mingw32", "i386-pc-windows-msvc", "arm-linux-gnueabihf", "arm-none-eabi", "riscv32-linux-gnu",
  "powerpc-linux-gnu", "mips-linux-gnu", "mipsel-linux-gnu",
];

export type Policy = "import" | "skip" | "rename";

interface Row {
  named: ParseCNamedType;
  status: "new" | "replaces" | "identical";
  policy: Policy;
  rename: string;
}

interface ProtoRow {
  name: string;
  declaration: string;
  entry: bigint | null;
  on: boolean;
}

/** -D/-U as typed: "FOO=1 BAR -DBAZ -UQUX" (spaces or commas). */
export function parseDefines(text: string): { defines: string[]; undefines: string[] } {
  const defines: string[] = [];
  const undefines: string[] = [];
  for (const t of text.split(/[\s,]+/).filter(Boolean)) {
    if (t.startsWith("-U")) undefines.push(t.slice(2));
    else defines.push(t.startsWith("-D") ? t.slice(2) : t);
  }
  return { defines: defines.filter(Boolean), undefines: undefines.filter(Boolean) };
}

/** The name a key binds ("struct pair" -> "pair"). */
function bare(key: string): string {
  return key.replace(/^(struct|union|enum|typedef|class) /, "");
}

let current: HeaderImportDialog | null = null;

/** Opens the dialog (one at a time). */
export function openHeaderImport(host: HeaderImportHost): HeaderImportDialog {
  current?.close();
  current = new HeaderImportDialog(host);
  return current;
}

/** The dialog open now (tests). */
export function headerImportDialog(): HeaderImportDialog | null {
  return current;
}

export class HeaderImportDialog {
  private backdrop: HTMLElement;
  private text: HTMLTextAreaElement;
  private name: HTMLInputElement;
  private path: HTMLInputElement;
  private includes: HTMLInputElement;
  private defines: HTMLInputElement;
  private profile: HTMLSelectElement;
  private asEnum: HTMLInputElement;
  private cpp: HTMLInputElement;
  private retype: HTMLInputElement;
  private status: HTMLElement;
  private results: HTMLElement;
  private parsed: ParseCResponse | null = null;
  private rows: Row[] = [];
  private protos: ProtoRow[] = [];
  private picked: Row | null = null;
  private diagAt: ParseCDiagnostic | null = null;
  private existing = new Map<string, string>();
  private busy = false;
  private importBtn: HTMLButtonElement;
  /** The header's text as parsed (pasted or uploaded; empty for a host file). */
  private source = "";
  private restore: HTMLElement | null;
  /** Archive mode: the sidecar's JSON. */
  private sidecar: HTMLTextAreaElement;
  private archive: boolean;

  constructor(private host: HeaderImportHost) {
    this.archive = !!host.archive;
    this.sidecar = h("textarea", { class: "hi-text hi-sidecar mono", rows: 4, spellcheck: "false", placeholder: "Paste the archive's sidecar (<name>.json) here, or upload both files", "data-testid": "hi-sidecar", "aria-label": "Sidecar JSON" });
    this.restore = document.activeElement as HTMLElement | null;
    this.text = h("textarea", { class: "hi-text mono", rows: 8, spellcheck: "false", placeholder: "Paste a header here, or upload one, or pick one on the daemon's host", "data-testid": "hi-text", "aria-label": "Header text" });
    this.name = h("input", { class: "filter", value: "header.h", spellcheck: "false", "aria-label": "File name", title: "Shown in diagnostics and kept as the import's version", "data-testid": "hi-name" });
    this.path = h("input", { class: "filter mono", spellcheck: "false", placeholder: "or a path on the daemon's host", "aria-label": "Path on the daemon's host", "data-testid": "hi-path" });
    this.includes = h("input", { class: "filter mono", spellcheck: "false", placeholder: "include folders on the daemon's host, comma-separated", "aria-label": "Include folders", "data-testid": "hi-includes" });
    this.defines = h("input", { class: "filter mono", spellcheck: "false", placeholder: "FOO=1 BAR -UBAZ", "aria-label": "Defines", "data-testid": "hi-defines" });
    this.defines.value = prefs.get("rk.headers.defines") ?? "";
    this.profile = h(
      "select",
      { class: "filter select", "aria-label": "Target", "data-testid": "hi-profile", title: "The data model the header is laid out for: the program's (its compiler spec), or a named target" },
      h("option", { value: "" }, "The program's target"),
      ...PROFILES.map((p) => h("option", { value: p }, p)),
    );
    this.asEnum = h("input", { type: "checkbox", "data-testid": "hi-enum" });
    this.asEnum.checked = true;
    this.cpp = h("input", { type: "checkbox", "data-testid": "hi-cpp" });
    this.retype = h("input", { type: "checkbox", "data-testid": "hi-retype" });
    this.status = h("div", { class: "dim hi-status", "data-testid": "hi-status", "aria-live": "polite" });
    this.results = h("div", { class: "hi-results", "data-testid": "hi-results" });
    this.importBtn = h("button", { class: "btn small primary", disabled: true, "data-testid": "hi-import", onclick: () => void this.import() }, "Import");
    const upload = async () => {
      const { file } = await pickFile();
      if (!file) return;
      this.text.value = await file.text();
      this.name.value = file.name;
      this.path.value = "";
    };
    const browse = async () => {
      const p = await browseHost(host.rk, { title: "A header on the daemon's host", remember: "rk.headers.lastDir" });
      if (!p) return;
      this.path.value = p;
      this.name.value = p.split("/").pop() ?? p;
    };
    const uploadArchive = async () => {
      const files = await pickFiles(".h,.json,.hpp,.txt");
      for (const f of files) {
        if (f.name.toLowerCase().endsWith(".json")) this.sidecar.value = await f.text();
        else {
          this.text.value = await f.text();
          this.name.value = f.name;
        }
      }
      if (files.length === 1) this.status.textContent = files[0].name.endsWith(".json") ? "Now the header (<name>.h)." : "Now the sidecar (<name>.json).";
    };
    const browseInclude = async () => {
      const p = await browseHost(host.rk, { title: "An include folder on the daemon's host", folders: true, remember: "rk.headers.lastDir" });
      if (p) this.includes.value = [this.includes.value.trim(), p].filter(Boolean).join(", ");
    };
    const archiveSource = h(
      "div",
      { class: "hi-source" },
      this.text,
      this.sidecar,
      h(
        "div",
        { class: "hi-row" },
        h("button", { class: "btn small", "data-testid": "hi-upload-archive", title: "Pick the header and its sidecar (both files)", onclick: () => void uploadArchive() }, "Upload archive…"),
        h("label", { class: "dim small-label" }, "name", this.name),
        h("span", { class: "spacer" }),
        h("button", { class: "btn small primary", "data-testid": "hi-parse", onclick: () => void this.parse() }, "Parse"),
      ),
    );
    if (this.archive) this.name.value = "types.h";
    const title = this.archive ? "Import a type archive" : "Import a C header";
    const box = h(
      "div",
      { class: "modal header-import", role: "dialog", "aria-modal": "true", "aria-label": title, "data-testid": "header-import", "data-mode": this.archive ? "archive" : "header" },
      h("div", { class: "modal-title" }, title),
      this.archive ? archiveSource : h(
        "div",
        { class: "hi-source" },
        this.text,
        h(
          "div",
          { class: "hi-row" },
          h("button", { class: "btn small", "data-testid": "hi-upload", onclick: () => void upload() }, "Upload file…"),
          h("button", { class: "btn small", "data-testid": "hi-browse", onclick: () => void browse() }, "Daemon host…"),
          this.path,
          h("label", { class: "dim small-label" }, "name", this.name),
        ),
        h("div", { class: "hi-row" }, h("label", { class: "dim small-label hi-grow" }, "-I", this.includes), h("button", { class: "btn small", "data-testid": "hi-add-include", onclick: () => void browseInclude() }, "Add folder…")),
        h("div", { class: "hi-row" }, h("label", { class: "dim small-label hi-grow" }, "-D/-U", this.defines), h("label", { class: "dim small-label" }, "target", this.profile)),
        h(
          "div",
          { class: "hi-row" },
          h("label", { class: "dim small-label", title: "Each file's integer #define constants as one enum, <file>_constants" }, this.asEnum, "#define constants as an enum"),
          h("label", { class: "dim small-label" }, this.cpp, "C++"),
          h("label", { class: "dim small-label", title: "Set each function's prototype from the header's prototype of the same name" }, this.retype, "retype functions by name from prototypes"),
          h("span", { class: "spacer" }),
          h("button", { class: "btn small primary", "data-testid": "hi-parse", onclick: () => void this.parse() }, "Parse"),
        ),
      ),
      this.status,
      this.results,
      h("div", { class: "types-actions" }, h("span", { class: "spacer" }), h("button", { class: "btn small", onclick: () => this.close() }, "Cancel"), this.importBtn),
    );
    this.backdrop = h("div", { class: "backdrop top" }, box);
    box.addEventListener("keydown", (e) => {
      e.stopPropagation();
      if (e.key === "Escape") this.close();
    });
    this.backdrop.addEventListener("mousedown", (e) => {
      if (e.target === this.backdrop) this.close();
    });
    overlayRoot().append(this.backdrop);
    this.text.focus();
  }

  close() {
    this.backdrop.remove();
    if (current === this) current = null;
    this.restore?.focus({ preventScroll: true });
  }

  /** Sets the text and options (tests), as typing them would. */
  fill(o: { text?: string; name?: string; path?: string; defines?: string; profile?: string; retype?: boolean; asEnum?: boolean; sidecar?: string }) {
    if (o.text !== undefined) this.text.value = o.text;
    if (o.sidecar !== undefined) this.sidecar.value = o.sidecar;
    if (o.name !== undefined) this.name.value = o.name;
    if (o.path !== undefined) this.path.value = o.path;
    if (o.defines !== undefined) this.defines.value = o.defines;
    if (o.profile !== undefined) this.profile.value = o.profile;
    if (o.retype !== undefined) this.retype.checked = o.retype;
    if (o.asEnum !== undefined) this.asEnum.checked = o.asEnum;
  }

  async parse(): Promise<void> {
    if (this.archive) return this.parseArchive();
    if (this.busy) return;
    const path = this.path.value.trim();
    const text = this.text.value;
    if (!path && !text.trim()) {
      this.status.textContent = "Paste a header, upload one, or pick one on the daemon's host.";
      return;
    }
    this.busy = true;
    this.status.textContent = "Parsing…";
    this.importBtn.disabled = true;
    const { defines, undefines } = parseDefines(this.defines.value);
    prefs.set("rk.headers.defines", this.defines.value);
    const t0 = performance.now();
    try {
      const r = await this.host.rk.types.parseC({
        programId: this.host.programId,
        sources: [path ? { kind: { case: "path", value: path } } : { kind: { case: "text", value: text }, name: this.name.value.trim() || "header.h" }],
        includeDirs: this.includes.value.split(",").map((x) => x.trim()).filter(Boolean),
        defines,
        undefines,
        profile: this.profile.value,
        options: { definesAsEnum: this.asEnum.checked, prototypes: this.retype.checked, cplusplus: this.cpp.checked },
      });
      // The functions the prototypes name first: the preview is whole when it shows.
      this.protos = [];
      if (this.retype.checked) {
        this.status.textContent = "Finding the functions the prototypes name…";
        await this.matchFunctions(r);
      }
      this.parsed = r;
      this.source = path ? "" : text;
      this.rows = r.named
        .filter((n) => !n.system)
        .map((n) => {
          const status = parsedStatus(n);
          return { named: n, status, policy: status === "identical" ? "skip" : "import", rename: "" } as Row;
        });
      this.picked = this.rows.find((x) => x.status === "replaces") ?? this.rows[0] ?? null;
      this.diagAt = null;
      const ms = performance.now() - t0;
      this.status.textContent = `Parsed for ${r.profile}${r.profileNotes.length ? ` (${r.profileNotes.join("; ")})` : ""} in ${ms < 1000 ? `${ms.toFixed(0)} ms` : `${(ms / 1000).toFixed(1)} s`}: ${r.errors} error${r.errors === 1 ? "" : "s"}, ${r.warnings} warning${r.warnings === 1 ? "" : "s"}${r.limitHit ? " · a limit stopped the parse" : ""}`;
    } catch (e) {
      this.parsed = null;
      this.rows = [];
      this.status.textContent = `Can't parse: ${errText(e)}`;
    } finally {
      this.busy = false;
    }
    this.paint();
  }

  /** Archive mode: the header with its sidecar, checked against its hashes. */
  private async parseArchive(): Promise<void> {
    if (this.busy) return;
    const text = this.text.value, sidecar = this.sidecar.value;
    if (!text.trim() || !sidecar.trim()) {
      this.status.textContent = "Give the archive's header and its sidecar (<name>.h and <name>.json).";
      return;
    }
    this.busy = true;
    this.status.textContent = "Parsing…";
    this.importBtn.disabled = true;
    try {
      const r = await this.host.rk.types.parseC({
        programId: this.host.programId,
        sources: [{ kind: { case: "text", value: text }, name: this.name.value.trim() || "types.h" }],
        archiveSidecar: sidecar,
      });
      this.protos = [];
      this.parsed = r;
      this.source = text;
      this.rows = r.named
        .filter((n) => !n.system)
        .map((n) => {
          // A name only the library archive defines: imported, so the program has its own.
          const status = n.existingLibrary ? "new" : parsedStatus(n);
          return { named: n, status, policy: status === "identical" ? "skip" : "import", rename: "" } as Row;
        });
      this.picked = this.rows.find((x) => x.status === "replaces") ?? this.rows[0] ?? null;
      this.diagAt = null;
      const c = r.archive!;
      const bad = c.mismatches.length;
      this.status.textContent =
        `Archive ${c.name}${c.origin ? ` (from ${c.origin})` : ""} for ${c.dataModel}: ${c.verified} of ${c.types} types match the sidecar's hashes` +
        (c.headerChanged ? " · the header isn't the one the sidecar was written with" : "") +
        (bad ? ` · ${bad} differ (${c.mismatches.slice(0, 4).map((m) => m.key).join(", ")}${bad > 4 ? ", …" : ""}): not importable` : "") +
        (r.profileNotes.length ? ` · ${r.profileNotes.join("; ")}` : "") +
        (r.errors ? ` · ${r.errors} error${r.errors === 1 ? "" : "s"}` : "");
    } catch (e) {
      this.parsed = null;
      this.rows = [];
      this.status.textContent = `Can't parse: ${errText(e)}`;
    } finally {
      this.busy = false;
    }
    this.paint();
  }

  /** The program's functions the prototypes name. */
  private async matchFunctions(r: ParseCResponse) {
    const protos = r.prototypes.slice(0, 5000);
    const out: ProtoRow[] = protos.map((p) => ({ name: p.name, declaration: p.declaration, entry: null, on: false }));
    let next = 0;
    const work = async () => {
      while (next < out.length) {
        const p = out[next++];
        try {
          const s = await this.host.rk.queries.listSymbols({ programId: this.host.programId, nameEquals: p.name, kinds: [SymbolKind.FUNCTION], page: { pageSize: 2 } });
          if (s.symbols.length === 1) {
            p.entry = s.symbols[0].address?.offset ?? null;
            p.on = p.entry !== null;
          }
        } catch {
          /* unmatched */
        }
      }
    };
    await Promise.all(Array.from({ length: 8 }, work));
    this.protos = out;
  }

  /** The existing definition's C, for a side-by-side view. */
  private async existingC(hash: string): Promise<string> {
    const have = this.existing.get(hash);
    if (have !== undefined) return have;
    try {
      const r = await this.host.rk.queries.getTypes({ programId: this.host.programId, hashes: [hash] });
      const c = r.types[0]?.cDefinition ?? "";
      this.existing.set(hash, c);
      return c;
    } catch (e) {
      return `(${errText(e)})`;
    }
  }

  private paint() {
    const r = this.parsed;
    if (!r) {
      this.results.replaceChildren();
      this.importBtn.disabled = true;
      return;
    }
    const group = (label: string, status: Row["status"]) => {
      const rows = this.rows.filter((x) => x.status === status);
      return h(
        "div",
        { class: "hi-group", "data-testid": `hi-bucket-${status}`, "data-count": rows.length },
        h("div", { class: "hi-group-head" }, `${label} (${rows.length})`),
        ...rows.map((x) => this.rowEl(x)),
      );
    };
    const tree = h(
      "div",
      { class: "hi-tree", role: "tree", "aria-label": "Types in the header" },
      group("New", "new"),
      group("Replaces the program's", "replaces"),
      group("Identical (nothing to do)", "identical"),
      this.retype.checked ? this.protoGroup() : null,
    );
    const detail = h("div", { class: "hi-detail", "data-testid": "hi-detail" });
    void this.paintDetail(detail);
    const diags = h(
      "div",
      { class: "hi-diags", "data-testid": "hi-diags", role: "list", "aria-label": "Diagnostics" },
      ...r.diagnostics.map((d) =>
        h(
          "div",
          {
            class: `hi-diag sev-${d.severity === ParseCSeverity.ERROR ? "error" : d.severity === ParseCSeverity.WARNING ? "warning" : "note"}` + (this.diagAt === d ? " active" : ""),
            role: "listitem",
            tabindex: "0",
            "data-testid": "hi-diag",
            onclick: () => {
              this.diagAt = d;
              this.picked = null;
              this.paint();
            },
          },
          h("span", { class: "mono dim" }, `${d.file}:${d.line}:${d.column}`),
          h("span", { class: "hi-sev" }, d.severity === ParseCSeverity.ERROR ? "error" : d.severity === ParseCSeverity.WARNING ? "warning" : "note"),
          h("span", {}, d.text),
        ),
      ),
    );
    this.results.replaceChildren(h("div", { class: "hi-split" }, tree, detail), r.diagnostics.length ? diags : h("div", { class: "dim" }, "No diagnostics."));
    const n = this.rows.filter((x) => x.policy !== "skip").length;
    const p = this.protos.filter((x) => x.on).length;
    // An archive also files its types under its categories.
    const filed = this.archive ? r.named.filter((x) => x.category && x.category !== x.existingCategory).length : 0;
    const blocked = this.archive && (r.archive?.mismatches.length ?? 0) > 0;
    this.importBtn.disabled = blocked || (!n && !p && !filed);
    this.importBtn.textContent = `Import ${n} type${n === 1 ? "" : "s"}${p ? ` and retype ${p} function${p === 1 ? "" : "s"}` : ""}${!n && filed ? ` (file ${filed} under the archive's categories)` : ""}`;
  }

  private rowEl(x: Row): HTMLElement {
    const sel = h(
      "select",
      { class: "filter select", "aria-label": `What to do with ${x.named.key}`, "data-testid": "hi-policy" },
      h("option", { value: "import" }, x.status === "replaces" ? "replace" : "import"),
      h("option", { value: "skip" }, "skip"),
      h("option", { value: "rename" }, "rename…"),
    );
    sel.value = x.policy;
    sel.addEventListener("change", () => {
      x.policy = sel.value as Policy;
      if (x.policy === "rename" && !x.rename) x.rename = `${bare(x.named.key)}_2`;
      this.paint();
    });
    sel.addEventListener("mousedown", (e) => e.stopPropagation());
    const ren = x.policy === "rename" ? h("input", { class: "filter mono hi-rename", value: x.rename, spellcheck: "false", "aria-label": "New name", "data-testid": "hi-rename" }) : null;
    ren?.addEventListener("input", () => (x.rename = ren.value.trim()));
    ren?.addEventListener("mousedown", (e) => e.stopPropagation());
    const constants = this.parsed?.constants.filter((k) => x.named.key.endsWith("_constants") && k.file && x.named.file === k.file).length ?? 0;
    return h(
      "div",
      {
        class: "hi-item" + (this.picked === x ? " active" : "") + (x.policy === "skip" ? " skipped" : ""),
        role: "treeitem",
        "data-key": x.named.key,
        "data-testid": "hi-item",
        onclick: () => {
          this.picked = x;
          this.diagAt = null;
          this.paint();
        },
      },
      h("span", { class: "mono hi-key" }, x.named.key),
      constants ? h("span", { class: "dim" }, `${constants} constants`) : null,
      h("span", { class: "dim mono" }, `${x.named.file.split("/").pop()}:${x.named.line}`),
      h("span", { class: "spacer" }),
      sel,
      ren,
    );
  }

  private protoGroup(): HTMLElement {
    const matched = this.protos.filter((p) => p.entry !== null);
    return h(
      "div",
      { class: "hi-group", "data-testid": "hi-bucket-prototypes", "data-count": matched.length },
      h("div", { class: "hi-group-head" }, `Functions to retype (${matched.length} of ${this.protos.length} prototypes name one)`),
      ...matched.map((p) => {
        const box = h("input", { type: "checkbox", "aria-label": `Retype ${p.name}`, "data-testid": "hi-proto" });
        box.checked = p.on;
        box.addEventListener("change", () => {
          p.on = box.checked;
          this.paint();
        });
        return h("label", { class: "hi-item", "data-name": p.name }, box, h("span", { class: "mono hi-key" }, p.declaration), h("span", { class: "dim mono" }, `0x${p.entry!.toString(16)}`));
      }),
    );
  }

  private async paintDetail(el: HTMLElement) {
    const d = this.diagAt;
    if (d) {
      const lines = this.source && d.file === (this.name.value.trim() || "header.h") ? this.source.split("\n") : null;
      const from = Math.max(1, d.line - 3);
      const ctx = lines ? lines.slice(from - 1, d.line + 2) : [d.sourceLine];
      const first = lines ? from : d.line;
      el.replaceChildren(
        h("div", { class: "hi-detail-head" }, `${d.file}, line ${d.line}`),
        h(
          "pre",
          { class: "types-c mono hi-source-view", "data-testid": "hi-line" },
          ...ctx.flatMap((t, i) => {
            const at = first + i === d.line;
            const line = h("div", { class: at ? "hi-line-at" : "" }, `${String(first + i).padStart(5)}  ${t}`);
            // The message under its line, the caret at its column.
            return at ? [line, h("div", { class: "hi-caret" }, `${" ".repeat(d.column ? 7 + d.column - 1 : 7)}^ ${d.text}`)] : [line];
          }),
        ),
      );
      return;
    }
    const x = this.picked;
    if (!x) {
      el.replaceChildren(h("div", { class: "dim" }, this.rows.length ? "Pick a type to see its definition." : "The header declares no types."));
      return;
    }
    const mine = h("pre", { class: "types-c mono", "data-testid": "hi-new-c" }, x.named.cDefinition);
    if (x.status !== "replaces") {
      el.replaceChildren(h("div", { class: "hi-detail-head" }, x.status === "new" ? `${x.named.key}: new` : `${x.named.key}: identical to the program's`), mine);
      return;
    }
    const theirs = h("pre", { class: "types-c mono", "data-testid": "hi-old-c" }, "…");
    const conflict = this.parsed?.conflicts.find((c) => c.namedKey === x.named.key);
    el.replaceChildren(
      h("div", { class: "hi-detail-head" }, `${x.named.key}: replaces the program's definition${conflict?.sameLayout ? " (same layout: names or member types differ)" : " (a different layout)"}`),
      h("div", { class: "hi-side" }, h("div", {}, h("div", { class: "dim" }, "The program's"), theirs), h("div", {}, h("div", { class: "dim" }, "The header's"), mine)),
    );
    theirs.textContent = await this.existingC(x.named.existingHash);
  }

  /** Defines the chosen types and binds their names (and retypes the chosen functions): one revision. */
  async import(): Promise<void> {
    const r = this.parsed;
    if (!r || this.busy) return;
    const chosen = this.rows.filter((x) => x.policy !== "skip");
    for (const x of chosen)
      if (x.policy === "rename" && !/^[A-Za-z_][\w:]*$/.test(x.rename)) {
        this.status.textContent = `${x.named.key}: "${x.rename}" isn't a name`;
        return;
      }
    const rename: Record<string, string> = {};
    for (const x of chosen) if (x.policy === "rename") rename[x.named.key] = x.rename;
    const protos = this.protos.filter((p) => p.on && p.entry !== null);
    this.busy = true;
    this.status.textContent = "Importing…";
    try {
      const plan = headerImportPlan(r, {
        keys: chosen.map((x) => x.named.key),
        rename,
        prototypes: protos.map((p) => p.name),
        ...(this.archive ? { includeLibrary: true, categories: "all" as const } : {}),
      });
      const bodies = [...plan.bodies];
      if (protos.length) {
        // The functions' types by hash, as the daemon will intern them (a
        // renamed type changes the hashes of everything that reaches it).
        const defines = bodies.filter((b) => b.kind.case === "defineType");
        const keys = await this.host.edits.validate(defines);
        for (const p of protos) {
          const proto = r.prototypes.find((x) => x.name === p.name)!;
          const hash = keys[plan.index.get(proto.index)!]?.sub;
          if (hash) bodies.push(Edits.retypeHashBody({ case: "address", address: p.entry! }, hash));
        }
      }
      if (!bodies.length) throw new Error("nothing to import: every chosen type is already the program's");
      const file = this.path.value.trim() ? this.path.value.trim().split("/").pop()! : this.name.value.trim() || "header.h";
      const runId = `${SESSION}:import-${Math.random().toString(16).slice(2, 10)}`;
      // import:header, unless signed in without the admin role (the daemon then stamps who we are).
      const asImporter = !auth.authEnabled || auth.identity?.role === Role.ADMIN;
      // An archive's import keeps its origin (the version), so exporting
      // these types again gives the same files.
      const what = this.archive ? `archive ${r.archive?.name || file}` : file;
      const provenance = create(ProvenanceSchema, {
        kind: asImporter ? ProvenanceKind.IMPORT : ProvenanceKind.UNSPECIFIED,
        id: asImporter ? (this.archive ? "archive" : "header") : "",
        version: this.archive ? (r.archive?.origin ?? "") : file,
        session: runId,
        tool: CLIENT_NAME,
        reason: `Import ${what}`,
      });
      const n = chosen.length;
      const res = await this.host.edits.bodiesAs(`Import ${what}`, bodies, provenance);
      toast(`Imported ${n} type${n === 1 ? "" : "s"} from ${what}${protos.length ? `, retyped ${protos.length} function${protos.length === 1 ? "" : "s"}` : ""}`, {
        action: { label: "Undo", run: () => void this.host.edits.undo().catch((e) => toast(errText(e), { kind: "error" })) },
      });
      await this.host.settle(res.revision);
      this.close();
      this.host.imported?.(chosen.map((x) => (x.policy === "rename" ? `${x.named.key.split(" ")[0]} ${x.rename}` : x.named.key)));
    } catch (e) {
      this.status.textContent = `Import failed: ${errText(e).replace(/^assertions\[\d+\]:\s*/, "")}`;
    } finally {
      this.busy = false;
    }
  }

  /** State for tests. */
  describe() {
    return {
      parsed: !!this.parsed,
      profile: this.parsed?.profile ?? "",
      buckets: {
        new: this.rows.filter((x) => x.status === "new").map((x) => x.named.key),
        replaces: this.rows.filter((x) => x.status === "replaces").map((x) => x.named.key),
        identical: this.rows.filter((x) => x.status === "identical").map((x) => x.named.key),
      },
      policies: Object.fromEntries(this.rows.map((x) => [x.named.key, x.policy === "rename" ? `rename:${x.rename}` : x.policy])),
      prototypes: this.protos.filter((p) => p.entry !== null).map((p) => p.name),
      diagnostics: this.parsed?.diagnostics.map((d) => `${d.line}: ${d.text}`) ?? [],
      status: this.status.textContent ?? "",
      archive: this.parsed?.archive ? { verified: this.parsed.archive.verified, types: this.parsed.archive.types, mismatches: this.parsed.archive.mismatches.map((m) => m.key), headerChanged: this.parsed.archive.headerChanged, origin: this.parsed.archive.origin } : null,
      importable: !this.importBtn.disabled,
    };
  }
}
