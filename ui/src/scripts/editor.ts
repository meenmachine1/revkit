// The script editor: a CodeMirror Python editor in a large dialog for
// per-user and per-project scripts (SaveScript, with the hash last read so
// someone else's change isn't overwritten). Shipped scripts open read-only,
// with "Copy to my scripts". Ctrl+S saves, Ctrl+Enter saves and runs,
// Escape closes (asking first when there are unsaved changes).

import { closeCompletion, completionStatus } from "@codemirror/autocomplete";
import { defaultKeymap, history, historyKeymap, indentWithTab } from "@codemirror/commands";
import { indentUnit } from "@codemirror/language";
import { EditorSelection, EditorState } from "@codemirror/state";
import { EditorView, highlightActiveLine, keymap, lineNumbers } from "@codemirror/view";
import { ScriptLibrary, type Revkit, type ScriptInfo } from "@revkit/api";
import { errText } from "../data/format";
import { choose, toast } from "../ui/dialogs";
import { h, overlayRoot } from "../ui/dom";
import { closeSignature, editorAssist } from "./assist";
import { python, pythonHighlight } from "./python";

export interface EditorHost {
  rk: Revkit;
  projectId: string;
  /** A script was saved (the list changes; trust is pinned). */
  saved(s: ScriptInfo): void;
  /** Ctrl+Enter / "Save and run". */
  run(s: ScriptInfo): void;
}

export interface OpenOptions {
  /** An existing script; else a new one. */
  script?: ScriptInfo;
  /** A new script's text and library. */
  source?: string;
  library?: ScriptLibrary;
  fileName?: string;
  /** Put the cursor on this 1-based line (a traceback's). */
  line?: number;
}

export const NEW_SCRIPT = `# @category My scripts
# @description What this script does
# @context program
from revkit.script import *

monitor.set_max(0)
for f in current_program.functions():
    monitor.check_cancelled()
    print(f.name)
`;

let current: { close: () => void } | null = null;

/** Opens the editor dialog. */
export async function openEditor(host: EditorHost, o: OpenOptions): Promise<void> {
  current?.close();
  let script = o.script;
  let source = o.source ?? "";
  let sha = "";
  if (script) {
    try {
      const r = await host.rk.scripts.getScript({ scriptId: script.scriptId });
      source = r.source;
      script = r.script ?? script;
      sha = script.sha256;
    } catch (e) {
      toast(`Can't read ${script.scriptId}: ${errText(e)}`, { kind: "error" });
      return;
    }
  }
  const readOnly = script ? !script.writable : false;
  let library = script?.library ?? o.library ?? ScriptLibrary.USER;
  const nameInput = h("input", {
    class: "se-name mono",
    spellcheck: "false",
    autocomplete: "off",
    "aria-label": "File name",
    "data-testid": "script-editor-name",
    placeholder: "my_script.py",
  });
  nameInput.value = script?.fileName ?? o.fileName ?? "";
  nameInput.disabled = !!script;
  const where = h("span", { class: "dim se-where", "data-testid": "script-editor-where" });
  const libSelect = h("select", { class: "se-lib", "aria-label": "Library", "data-testid": "script-editor-library" });
  for (const [v, label] of [
    [ScriptLibrary.USER, "My scripts"],
    [ScriptLibrary.PROJECT, `Project ${host.projectId}`],
  ] as const) {
    const opt = h("option", { value: String(v) }, label);
    libSelect.append(opt);
  }
  libSelect.value = String(library);
  libSelect.hidden = !!script;
  libSelect.onchange = () => (library = Number(libSelect.value) as ScriptLibrary);
  const status = h("span", { class: "dim se-status", "data-testid": "script-editor-status" });
  const dirtyMark = h("span", { class: "se-dirty", title: "Unsaved changes" });
  let dirty = false;
  const setDirty = (d: boolean) => {
    dirty = d;
    dirtyMark.textContent = d ? "●" : "";
  };
  const describe = () => {
    where.textContent = script ? `${script.scriptId} · sha256 ${script.sha256.slice(0, 12)}${readOnly ? " · read-only" : ""}` : "new script";
  };
  describe();

  const save = async (): Promise<ScriptInfo | null> => {
    if (readOnly) {
      toast("Shipped scripts are read-only: copy it to your scripts to change it");
      return null;
    }
    const fileName = (script?.fileName ?? nameInput.value.trim()).replace(/^(?!.*\.py$)(.+)$/, "$1.py");
    if (!/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,60}\.py$/.test(fileName)) {
      status.textContent = "A file name: letters, digits, _ . - ending in .py";
      nameInput.focus();
      return null;
    }
    try {
      const r = await host.rk.scripts.saveScript({
        library: script?.library ?? library,
        projectId: (script?.library ?? library) === ScriptLibrary.PROJECT ? (script?.projectId || host.projectId) : "",
        fileName,
        source: view.state.doc.toString(),
        expectedSha256: sha,
      });
      if (r.script) {
        script = r.script;
        sha = r.script.sha256;
        nameInput.value = r.script.fileName;
        nameInput.disabled = true;
        libSelect.hidden = true;
        describe();
        host.saved(r.script);
      }
      setDirty(false);
      status.textContent = `Saved ${new Date().toLocaleTimeString()}`;
      return script ?? null;
    } catch (e) {
      status.textContent = errText(e);
      return null;
    }
  };
  const saveAndRun = async () => {
    const s = readOnly ? script! : await save();
    if (s) {
      close();
      host.run(s);
    }
  };

  const view = new EditorView({
    state: EditorState.create({
      doc: source,
      extensions: [
        lineNumbers(),
        highlightActiveLine(),
        history(),
        indentUnit.of("    "),
        EditorState.tabSize.of(4),
        python,
        pythonHighlight,
        // Completion of the script API and Ghidra's names, and signature
        // help on "(" (assist.ts; the index is script-api.json).
        editorAssist(),
        EditorState.readOnly.of(readOnly),
        EditorView.editable.of(!readOnly),
        keymap.of([
          { key: "Mod-s", preventDefault: true, run: () => (void save(), true) },
          { key: "Mod-Enter", preventDefault: true, run: () => (void saveAndRun(), true) },
          indentWithTab,
          ...historyKeymap,
          ...defaultKeymap,
        ]),
        EditorView.updateListener.of((u) => {
          if (u.docChanged) setDirty(true);
        }),
        EditorView.contentAttributes.of({ "aria-label": "Script source", "data-testid": "script-editor-text" }),
        EditorView.theme({ "&": { height: "100%" }, ".cm-scroller": { fontFamily: "var(--mono)", fontSize: "13px" } }),
      ],
    }),
  });

  const close = () => {
    view.destroy();
    backdrop.remove();
    document.removeEventListener("keydown", onKey, true);
    if (current?.close === close) current = null;
  };
  const tryClose = async () => {
    if (dirty && !readOnly) {
      const v = await choose("Discard the unsaved changes?", [
        { label: "Keep editing", value: "keep" },
        { label: "Discard", value: "discard" },
      ]);
      if (v !== "discard") return view.focus();
    }
    close();
  };
  const copyToMine = async () => {
    if (!script) return;
    close();
    await openEditor(host, { source: view.state.doc.toString(), library: ScriptLibrary.USER, fileName: script.fileName });
  };
  const buttons = h(
    "div",
    { class: "se-buttons" },
    status,
    h("span", { class: "spacer" }),
    readOnly
      ? h("button", { class: "btn", type: "button", "data-testid": "script-editor-copy", onclick: () => void copyToMine() }, "Copy to my scripts")
      : h("button", { class: "btn", type: "button", "data-testid": "script-editor-save", title: "Ctrl+S", onclick: () => void save() }, "Save"),
    h("button", { class: "btn primary", type: "button", "data-testid": "script-editor-run", title: "Ctrl+Enter", onclick: () => void saveAndRun() }, readOnly ? "Run" : "Save and run"),
    h("button", { class: "btn", type: "button", "data-testid": "script-editor-close", onclick: () => void tryClose() }, "Close"),
  );
  const body = h("div", { class: "se-body" }, view.dom);
  const box = h(
    "div",
    { class: "modal script-editor", role: "dialog", "aria-modal": "true", "aria-label": "Script editor", "data-testid": "script-editor" },
    h("div", { class: "se-head" }, h("span", { class: "modal-title" }, "Script"), dirtyMark, libSelect, nameInput, where),
    body,
    buttons,
    h("div", { class: "modal-hint" }, `${readOnly ? "" : "Ctrl+S save · "}Ctrl+Enter ${readOnly ? "run" : "save and run"} · Esc close`),
  );
  const backdrop = h("div", { class: "backdrop top" }, box);
  // Escape anywhere in the dialog closes it (the editor's own keys first).
  const onKey = (e: KeyboardEvent) => {
    if (!box.contains(e.target as Node) && e.target !== document.body) return;
    if (e.key === "Escape" && !document.querySelector("[data-testid=choose]")) {
      e.preventDefault();
      e.stopPropagation();
      // Escape closes the completion list or the signature first.
      if (completionStatus(view.state)) closeCompletion(view);
      else if (!closeSignature(view)) void tryClose();
    }
  };
  document.addEventListener("keydown", onKey, true);
  box.addEventListener("keydown", (e) => e.stopPropagation());
  overlayRoot().append(backdrop);
  current = { close };
  if (o.line && o.line > 0 && o.line <= view.state.doc.lines) {
    const line = view.state.doc.line(o.line);
    view.dispatch({ selection: EditorSelection.cursor(line.from), effects: EditorView.scrollIntoView(line.from, { y: "center" }) });
    box.dataset.line = String(o.line);
  }
  if (!script) nameInput.focus();
  else view.focus();
}

/** Whether the editor dialog is open (tests). */
export function editorOpen(): boolean {
  return current !== null;
}
