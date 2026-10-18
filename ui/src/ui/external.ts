// External decompilers (api_minor 92, feature "external-decompilers";
// docs/providers.md, docs/ui.md "External decompilers"): a dedicated
// decompiler's source for bytecode (ILSpy's C# for a .NET assembly, jadx's
// Java for a DEX or APK, Vineflower's for a jar, pycdc, unluac,
// wasm-decompile, webcrack), run by the daemon in its sandbox
// (ProviderService.DecompileExternal) and read back file by file
// (ReadProviderOutput), with syntax highlighting.
//
// Two places show it: the decompiler pane, when the program is bytecode
// (a bar switches between the provider's source and Ghidra's C), and the
// file system browser's "Decompile with jadx…" (a dialog with the output's
// files on the left).

import { drawSelection, EditorView, lineNumbers } from "@codemirror/view";
import { Compartment, EditorState } from "@codemirror/state";
import {
  ProviderRunStatus, type DecompileExternalResponse, type ListProvidersResponse, type ProviderInfo, type ProviderInput,
  type ProviderOutputFile, type Revkit,
} from "@revkit/api";
import { errText } from "../data/format";
import { h, overlayRoot } from "./dom";
import { languageTitle, sourceLanguage } from "./sourcehl";

export const EXTERNAL_FEATURE = "external-decompilers";

export type ProviderTarget = { programId: string } | { sessionId: string; path: string };

export function providerInput(t: ProviderTarget): ProviderInput {
  return ("programId" in t
    ? { source: { case: "programId", value: t.programId } }
    : { source: { case: "file", value: { sessionId: t.sessionId, path: t.path } } }) as ProviderInput;
}

/** What an input is and which providers take it (ListProviders with the input). */
export async function providersFor(rk: Revkit, t: ProviderTarget): Promise<ListProvidersResponse> {
  return rk.providers.listProviders({ input: providerInput(t) });
}

/** The providers that take the input, in order of preference. */
export function applicable(r: ListProvidersResponse): ProviderInfo[] {
  return r.applicable.map((n) => r.providers.find((p) => p.name === n)).filter((p): p is ProviderInfo => !!p);
}

export function statusText(r: DecompileExternalResponse): string {
  const names: Record<number, string> = {
    [ProviderRunStatus.OK]: "",
    [ProviderRunStatus.FAILED]: "failed",
    [ProviderRunStatus.CRASHED]: "crashed",
    [ProviderRunStatus.TIMEOUT]: "timed out",
    [ProviderRunStatus.OUT_OF_MEMORY]: "ran out of memory",
    [ProviderRunStatus.OUTPUT_LIMIT]: "wrote more than the output cap",
    [ProviderRunStatus.SANDBOX_ERROR]: "couldn't be sandboxed",
  };
  return names[r.status] ?? "";
}

/** A read-only, highlighted view of one source file. */
export class SourceViewer {
  readonly el: HTMLElement;
  private view: EditorView;
  private lang = new Compartment();

  constructor(label: string) {
    this.el = h("div", { class: "ext-code", "data-testid": "ext-code" });
    this.view = new EditorView({
      parent: this.el,
      state: EditorState.create({
        doc: "",
        extensions: [
          EditorState.readOnly.of(true),
          EditorView.editable.of(false),
          EditorView.contentAttributes.of({ tabindex: "0", "aria-label": label }),
          lineNumbers(),
          drawSelection(),
          this.lang.of([]),
        ],
      }),
    });
  }

  show(text: string, language: string) {
    this.view.dispatch({
      changes: { from: 0, to: this.view.state.doc.length, insert: text },
      effects: this.lang.reconfigure(sourceLanguage(language)),
      selection: { anchor: 0 },
      scrollIntoView: true,
    });
    this.el.dataset.language = language;
  }

  text(): string {
    return this.view.state.doc.toString();
  }
}

const decoder = new TextDecoder("utf-8");

/**
 * One input's external decompilation: choose the provider, run it (or take
 * the cached result), pick a file, read and show it. `files` is a <select>
 * in the pane and a list with a filter in the dialog.
 */
export class ExternalSource {
  readonly el: HTMLElement;
  readonly viewer: SourceViewer;
  private providerSel: HTMLSelectElement;
  private fileSel: HTMLSelectElement | null = null;
  private fileList: HTMLElement | null = null;
  private filter: HTMLInputElement | null = null;
  private status: HTMLElement;
  private result: DecompileExternalResponse | null = null;
  private seq = 0;
  /** Called when a run finishes: the provider's name, or "" (failed). */
  onLoaded?: (r: DecompileExternalResponse | null) => void;

  constructor(
    private rk: Revkit,
    private target: ProviderTarget,
    private list: ListProvidersResponse,
    layout: "pane" | "dialog",
  ) {
    this.viewer = new SourceViewer("Decompiled source");
    this.providerSel = h("select", { class: "ext-provider", "aria-label": "External decompiler", "data-testid": "ext-provider" }) as HTMLSelectElement;
    for (const p of applicable(list)) {
      const o = h("option", { value: p.name }, `${p.title}${p.version ? " " + p.version : ""} (${languageTitle(p.language)})`) as HTMLOptionElement;
      o.disabled = !p.available;
      if (!p.available) o.title = p.reason;
      this.providerSel.append(o);
    }
    this.providerSel.value = list.defaultProvider;
    this.providerSel.addEventListener("change", () => void this.run(this.providerSel.value));
    this.status = h("span", { class: "ext-status dim", "data-testid": "ext-status", role: "status" });
    const again = h("button", {
      class: "btn small",
      type: "button",
      "data-testid": "ext-rerun",
      title: "Run the decompiler again rather than take the cached result",
      text: "Run again",
      onclick: () => void this.run(this.providerSel.value, true),
    });
    const tools = h("div", { class: "ext-tools" }, this.providerSel);
    if (layout === "pane") {
      this.fileSel = h("select", { class: "ext-file", "aria-label": "File of the output", "data-testid": "ext-file" }) as HTMLSelectElement;
      this.fileSel.addEventListener("change", () => void this.open(this.fileSel!.value));
      tools.append(this.fileSel);
    }
    tools.append(again, this.status);
    if (layout === "pane") {
      this.el = h("div", { class: "ext-pane", "data-testid": "ext-pane" }, tools, this.viewer.el);
    } else {
      this.filter = h("input", { class: "filter ext-filter", spellcheck: "false", placeholder: "Filter files", "aria-label": "Filter files", "data-testid": "ext-filter" }) as HTMLInputElement;
      this.fileList = h("div", { class: "ext-files", role: "listbox", "aria-label": "Files of the output", "data-testid": "ext-files" });
      this.filter.addEventListener("input", () => {
        const q = this.filter!.value.trim().toLowerCase();
        for (const row of this.fileList!.querySelectorAll<HTMLElement>(".ext-f")) row.hidden = !!q && !row.dataset.path!.toLowerCase().includes(q);
      });
      this.el = h(
        "div",
        { class: "ext-dialog-body" },
        tools,
        h("div", { class: "ext-split" }, h("div", { class: "ext-side" }, this.filter, this.fileList), this.viewer.el),
      );
    }
  }

  /** Runs (or takes from the cache) the provider and shows its main file. */
  async run(provider = this.providerSel.value, refresh = false): Promise<DecompileExternalResponse | null> {
    const seq = ++this.seq;
    const p = this.list.providers.find((x) => x.name === provider);
    this.say(`${p?.title ?? provider}: decompiling…`);
    try {
      const r = await this.rk.providers.decompileExternal({ input: providerInput(this.target), provider, refresh });
      if (seq !== this.seq) return null;
      this.result = r;
      this.fillFiles(r.files);
      const failed = statusText(r);
      const what = `${r.files.length} file${r.files.length === 1 ? "" : "s"}`;
      this.say(
        failed
          ? `${p?.title ?? provider} ${failed}: ${r.detail}${r.stderrTail ? ` · ${r.stderrTail.trim().split("\n").pop()}` : ""}`
          : `${p?.title ?? provider} ${r.providerVersion} · ${what} · ${r.cached ? "cached" : `${r.seconds.toFixed(1)} s`}`,
        failed ? "error" : "",
      );
      this.status.title = `${r.inputKind?.description ?? ""} · sha256 ${r.inputSha256}\nsandbox: ${r.sandbox}` + (r.stderrTail ? `\n\n${r.stderrTail.slice(-1500)}` : "");
      if (r.mainFile) {
        this.select(r.mainFile);
        if (!r.mainTruncated) this.viewer.show(r.mainText, langOf(r.files, r.mainFile));
        else await this.open(r.mainFile);
      } else {
        this.viewer.show(failed ? `// ${p?.title ?? provider} ${failed}: ${r.detail}\n${r.stderrTail.split("\n").map((l) => "// " + l).join("\n")}` : "// No output.", "java");
      }
      this.onLoaded?.(r);
      return r;
    } catch (e) {
      if (seq !== this.seq) return null;
      this.say(errText(e), "error");
      this.viewer.show(`// ${errText(e)}`, "java");
      this.onLoaded?.(null);
      return null;
    }
  }

  /** Reads one file of the result and shows it. */
  async open(path: string) {
    const r = this.result;
    if (!r) return;
    this.select(path);
    const lang = langOf(r.files, path);
    if (lang === "binary") {
      this.viewer.show(`// ${path}: binary (${r.files.find((f) => f.path === path)?.size ?? 0} bytes)`, "text");
      return;
    }
    if (path === r.mainFile && !r.mainTruncated) {
      this.viewer.show(r.mainText, lang);
      return;
    }
    const seq = this.seq;
    try {
      const out = await this.rk.providers.readProviderOutput({ input: providerInput(this.target), provider: r.provider, path, maxBytes: 8 << 20 });
      if (seq !== this.seq) return;
      this.viewer.show(decoder.decode(out.data) + (out.truncated ? "\n// … (more than 8 MiB; truncated)" : ""), lang);
    } catch (e) {
      this.viewer.show(`// ${errText(e)}`, "text");
    }
  }

  private select(path: string) {
    if (this.fileSel) this.fileSel.value = path;
    for (const row of this.fileList?.querySelectorAll<HTMLElement>(".ext-f") ?? []) row.classList.toggle("active", row.dataset.path === path);
  }

  private fillFiles(files: ProviderOutputFile[]) {
    if (this.fileSel) {
      this.fileSel.replaceChildren(...files.map((f) => h("option", { value: f.path }, f.path)));
      this.fileSel.hidden = files.length < 2;
    }
    if (this.fileList) {
      this.fileList.replaceChildren(
        ...files.map((f) =>
          h(
            "div",
            {
              class: `ext-f lang-${f.language}`,
              role: "option",
              "data-path": f.path,
              "data-testid": "ext-f",
              title: `${f.path} · ${f.size} bytes`,
              onclick: () => void this.open(f.path),
            },
            f.path,
          ),
        ),
      );
    }
  }

  private say(text: string, kind = "") {
    this.status.textContent = text;
    this.status.className = "ext-status " + (kind || "dim");
  }

  get response(): DecompileExternalResponse | null {
    return this.result;
  }
}

function langOf(files: ProviderOutputFile[], path: string): string {
  return files.find((f) => f.path === path)?.language ?? "text";
}

/** File system browser: "Decompile with jadx…" on a file. */
export function showExternalDialog(rk: Revkit, target: ProviderTarget, list: ListProvidersResponse, provider: string, title: string) {
  const restore = document.activeElement as HTMLElement | null;
  const src = new ExternalSource(rk, target, list, "dialog");
  const close = () => {
    backdrop.remove();
    restore?.focus({ preventScroll: true });
  };
  const box = h(
    "div",
    { class: "modal ext-dialog", role: "dialog", tabindex: "-1", "aria-label": title, "data-testid": "ext-dialog" },
    h("div", { class: "libs-head" }, h("div", { class: "modal-title" }, title), h("span", { class: "spacer" }), h("button", { class: "btn", type: "button", "data-testid": "ext-close", onclick: close, text: "Close" })),
    src.el,
    h("div", { class: "modal-hint" }, `${list.inputKind?.description ?? ""} · run in the daemon's sandbox (${list.sandbox}) · Esc closes`),
  );
  const backdrop = h("div", { class: "backdrop top" }, box);
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
  void src.run(provider);
}

/**
 * The decompiler pane's bar for a bytecode program: switch between the
 * provider's source and Ghidra's C. `setExternal(true)` hides the C view.
 */
export class ExternalPaneBar {
  readonly bar: HTMLElement;
  readonly source: ExternalSource;
  private mode: HTMLSelectElement;
  private ran = false;

  constructor(
    rk: Revkit,
    programId: string,
    list: ListProvidersResponse,
    private host: { cm: HTMLElement; hideNative: (hidden: boolean) => void; title: HTMLElement },
  ) {
    this.source = new ExternalSource(rk, { programId }, list, "pane");
    this.mode = h("select", { class: "ext-mode", "aria-label": "Decompiler view", "data-testid": "ext-mode" }) as HTMLSelectElement;
    const best = applicable(list).find((p) => p.available);
    this.mode.append(
      h("option", { value: "external" }, best ? `${languageTitle(best.language)} (external decompiler)` : "Source (no external decompiler installed)") as HTMLOptionElement,
      h("option", { value: "native" }, "C (Ghidra's decompiler)") as HTMLOptionElement,
    );
    const what = list.inputKind?.description ?? "bytecode";
    const hint = best
      ? ""
      : ` · ${applicable(list).map((p) => p.title).join(" or ") || "no provider"} isn't available: ${applicable(list)[0]?.reason ?? ""}`;
    this.bar = h(
      "div",
      { class: "ext-bar", "data-testid": "ext-bar" },
      h("span", { class: "ext-kind", "data-testid": "ext-kind" }, what),
      this.mode,
      h("span", { class: "dim ext-hint" }, hint),
    );
    this.mode.addEventListener("change", () => this.setExternal(this.mode.value === "external"));
    this.source.el.hidden = true;
    host.cm.after(this.source.el);
  }

  /** Shows the provider's source (running it the first time) or the C. */
  setExternal(on: boolean) {
    this.mode.value = on ? "external" : "native";
    this.source.el.hidden = !on;
    this.host.cm.hidden = on;
    this.host.hideNative(on);
    if (on && !this.ran) {
      this.ran = true;
      void this.source.run();
    }
  }

  get external(): boolean {
    return this.mode.value === "external";
  }
}
