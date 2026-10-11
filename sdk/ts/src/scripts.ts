// Scripts the daemon runs (ScriptService, api_minor 31, feature "scripts-host";
// docs/scripting.md): a run as one call with handlers for its output,
// progress, prompts and the trust confirmation, and helpers over script
// metadata (context-menu scripts, key bindings, the category tree).
import type { Revkit } from "./index";
import type {
  ConsoleResult,
  CompleteConsoleResponse,
  ScriptError,
  ScriptInfo,
  ScriptPrompt,
  ScriptResult,
  ScriptStarted,
  ScriptTrustRequired,
  SetupScriptPythonResult,
} from "./gen/revkit/v1/script_pb";

export const SCRIPTS_HOST_FEATURE = "scripts-host";
/** The Python console: RunScript{interactive}, CancelScript{interrupt} (api_minor 43). */
export const SCRIPT_CONSOLE_FEATURE = "script-console";
/** ScriptService.CompleteConsole (api_minor 43). */
export const SCRIPT_COMPLETION_FEATURE = "script-completion";
/** ScriptService.SetupScriptPython (api_minor 33). */
export const SCRIPTS_SETUP_FEATURE = "scripts-setup";

/** Makes the Python environment the daemon runs scripts with
 * (~/.local/share/revkit/pyenv, as `rk-script setup` does), streaming what
 * the steps print to `onOutput`; resolves with the result (`ok`, the
 * Python found, or the error). Aborting `signal` stops it. */
export async function setupScriptPython(
  rk: Revkit,
  opts: { force?: boolean; onOutput?(text: string): void; signal?: AbortSignal } = {},
): Promise<SetupScriptPythonResult> {
  for await (const ev of rk.scripts.setupScriptPython({ force: opts.force ?? false }, { signal: opts.signal })) {
    const e = ev.event;
    if (e.case === "output") opts.onOutput?.(e.value);
    else if (e.case === "result") return e.value;
  }
  throw new Error("SetupScriptPython ended without a result");
}

/** What a prompt handler returns: the answer's text (a list for "choices"),
 * or null when the user dismissed it (the run is then cancelled). */
export type PromptAnswer = string | string[] | null;

export interface RunScriptHandlers {
  onStarted?(s: ScriptStarted): void;
  onOutput?(text: string, stream: string): void;
  onProgress?(current: bigint, maximum: bigint, message: string): void;
  /** Asked for each prompt; the run waits for the answer. */
  onPrompt?(p: ScriptPrompt, runId: string): Promise<PromptAnswer>;
  /** The caller hasn't confirmed this script's text: show `t.source` and
   * `t.script.sha256`; true runs it (pinning the hash), false doesn't. */
  onTrust?(t: ScriptTrustRequired): Promise<boolean>;
  signal?: AbortSignal;
}

export interface RunScriptParams {
  scriptId: string;
  programId: string;
  /** --arg name=value: fills `args` and answers the ask_* of that name. */
  args?: Record<string, string>;
  /** current_address (and current_function) and current_selection. */
  address?: bigint;
  selection?: [bigint, bigint];
  /** The sha256 the user already confirmed. */
  confirmSha256?: string;
  reason?: string;
}

export interface RunScriptOutcome {
  runId: string;
  /** "ok", "error", "cancelled", or "untrusted" when onTrust declined (or
   * there was none). */
  status: string;
  result?: ScriptResult;
  error?: ScriptError;
  trust?: ScriptTrustRequired;
}

/** Runs a script and waits for its end, answering prompts with the
 * handlers. Aborting `signal` cancels the run. */
export async function runScript(rk: Revkit, req: RunScriptParams, h: RunScriptHandlers = {}): Promise<RunScriptOutcome> {
  let confirm = req.confirmSha256 ?? "";
  const context = {
    address: req.address === undefined ? undefined : { offset: req.address },
    selection: req.selection ? { first: { offset: req.selection[0] }, last: { offset: req.selection[1] } } : undefined,
  };
  for (let attempt = 0; attempt < 2; attempt++) {
    let runId = "";
    let trust: ScriptTrustRequired | undefined;
    const onAbort = () => {
      if (runId) void rk.scripts.cancelScript({ runId }).catch(() => undefined);
    };
    h.signal?.addEventListener("abort", onAbort);
    try {
      for await (const ev of rk.scripts.runScript(
        { scriptId: req.scriptId, programId: req.programId, args: req.args ?? {}, context, confirmSha256: confirm, reason: req.reason ?? "" },
        { signal: h.signal },
      )) {
        if (ev.runId) runId = ev.runId;
        const e = ev.event;
        switch (e.case) {
          case "started":
            h.onStarted?.(e.value);
            break;
          case "output":
            h.onOutput?.(e.value.text, e.value.stream);
            break;
          case "progress":
            h.onProgress?.(e.value.current, e.value.maximum, e.value.message);
            break;
          case "prompt": {
            const p = e.value;
            let answer: PromptAnswer = null;
            try {
              answer = h.onPrompt ? await h.onPrompt(p, runId) : null;
            } catch {
              answer = null;
            }
            await rk.scripts.answerPrompt({
              runId,
              promptId: p.promptId,
              cancelled: answer === null,
              value: typeof answer === "string" ? answer : "",
              values: Array.isArray(answer) ? answer : [],
            });
            break;
          }
          case "trustRequired":
            trust = e.value;
            break;
          case "result":
            return { runId, status: e.value.status || "ok", result: e.value };
          case "error":
            return { runId, status: e.value.result?.status || "error", error: e.value, result: e.value.result };
        }
      }
    } finally {
      h.signal?.removeEventListener("abort", onAbort);
    }
    if (!trust) return { runId, status: "error" };
    if (attempt === 0 && h.onTrust && (await h.onTrust(trust))) {
      confirm = trust.script?.sha256 ?? "";
      continue;
    }
    return { runId, status: "untrusted", trust };
  }
  return { runId: "", status: "untrusted" };
}

/** The scripts that apply where the user is: "function" scripts with a
 * function at the cursor, "selection" scripts with a selection, "address"
 * scripts anywhere in the program. */
export function scriptsForContext(scripts: ScriptInfo[], where: { function?: boolean; selection?: boolean; address?: boolean }): ScriptInfo[] {
  return scripts.filter(
    (s) =>
      (s.context === "function" && where.function) ||
      (s.context === "selection" && where.selection) ||
      (s.context === "address" && where.address),
  );
}

/** An @keybinding ("ctrl shift R", "Ctrl-Alt-F5", "alt+x") as the UI's
 * key names ("Ctrl+Shift+R"); "" when it names no key. */
export function normalizeKeybinding(text: string): string {
  const parts = text.trim().split(/[\s+-]+/).filter(Boolean);
  if (!parts.length) return "";
  const mods = new Set<string>();
  let key = "";
  for (const p of parts) {
    const l = p.toLowerCase();
    if (l === "ctrl" || l === "control") mods.add("Ctrl");
    else if (l === "cmd" || l === "meta" || l === "command") mods.add("Meta");
    else if (l === "alt" || l === "option") mods.add("Alt");
    else if (l === "shift") mods.add("Shift");
    else key = p.length === 1 ? p.toUpperCase() : p[0].toUpperCase() + p.slice(1).toLowerCase();
  }
  if (!key) return "";
  return [...["Ctrl", "Meta", "Alt", "Shift"].filter((m) => mods.has(m)), key].join("+");
}

export interface ScriptCategory {
  name: string;
  path: string;
  children: ScriptCategory[];
  scripts: ScriptInfo[];
}

/** Scripts grouped by their "A/B" categories (uncategorized ones under
 * "Other"), children and scripts sorted by name. */
export function scriptCategoryTree(scripts: ScriptInfo[]): ScriptCategory {
  const root: ScriptCategory = { name: "", path: "", children: [], scripts: [] };
  for (const s of scripts) {
    let node = root;
    for (const part of (s.category || "Other").split("/").map((p) => p.trim()).filter(Boolean)) {
      let child = node.children.find((c) => c.name === part);
      if (!child) {
        child = { name: part, path: node.path ? `${node.path}/${part}` : part, children: [], scripts: [] };
        node.children.push(child);
      }
      node = child;
    }
    node.scripts.push(s);
  }
  const sort = (n: ScriptCategory) => {
    n.children.sort((a, b) => a.name.localeCompare(b.name));
    n.scripts.sort((a, b) => a.name.localeCompare(b.name));
    n.children.forEach(sort);
  };
  sort(root);
  return root;
}

export interface ConsoleRunParams {
  programId: string;
  /** A statement, a block or a paste; "" only opens the console. */
  input: string;
  /** current_address (and current_function) and current_selection first. */
  address?: bigint;
  selection?: [bigint, bigint];
  /** Bind Ghidra's names (currentProgram, getFunctionAt, ...) too. */
  ghidraNames?: boolean;
}

export interface ConsoleRunHandlers {
  onStarted?(s: ScriptStarted): void;
  onOutput?(text: string, stream: string): void;
  /** ask_* and input() in the statement; null dismisses (it is interrupted). */
  onPrompt?(p: ScriptPrompt, runId: string): Promise<PromptAnswer>;
  signal?: AbortSignal;
}

export interface ConsoleOutcome {
  /** The console's run id (UpdateContext, CancelScript). */
  runId: string;
  started?: ScriptStarted;
  /** "ok", "error", "interrupted", "exit"; "" with `more`; "died" when the
   * host died during it (`error` says how). */
  status: string;
  more: boolean;
  result?: ConsoleResult;
  error: string;
}

/** Runs `input` in the caller's Python console of a program (one live host
 * per caller and program on the daemon; feature "script-console") and waits
 * for its end. Aborting `signal` interrupts the statement (KeyboardInterrupt);
 * the console stays. */
export async function consoleRun(rk: Revkit, req: ConsoleRunParams, h: ConsoleRunHandlers = {}): Promise<ConsoleOutcome> {
  const context =
    req.address === undefined && !req.selection
      ? undefined
      : {
          address: req.address === undefined ? undefined : { offset: req.address },
          selection: req.selection ? { first: { offset: req.selection[0] }, last: { offset: req.selection[1] } } : undefined,
        };
  const out: ConsoleOutcome = { runId: "", status: "", more: false, error: "" };
  let interrupted = false;
  const onAbort = () => {
    if (out.runId && !interrupted) {
      interrupted = true;
      void rk.scripts.cancelScript({ runId: out.runId, interrupt: true }).catch(() => undefined);
    }
  };
  h.signal?.addEventListener("abort", onAbort);
  try {
    // The stream is not aborted with the signal: the statement is
    // interrupted and its result still arrives.
    for await (const ev of rk.scripts.runScript({ programId: req.programId, interactive: true, input: req.input, ghidraNames: req.ghidraNames ?? false, context })) {
      if (ev.runId) out.runId = ev.runId;
      const e = ev.event;
      switch (e.case) {
        case "started":
          out.started = e.value;
          h.onStarted?.(e.value);
          if (h.signal?.aborted) onAbort();
          break;
        case "output":
          h.onOutput?.(e.value.text, e.value.stream);
          break;
        case "prompt": {
          const p = e.value;
          let answer: PromptAnswer = null;
          try {
            answer = h.onPrompt ? await h.onPrompt(p, out.runId) : null;
          } catch {
            answer = null;
          }
          await rk.scripts.answerPrompt({
            runId: out.runId,
            promptId: p.promptId,
            cancelled: answer === null,
            value: typeof answer === "string" ? answer : "",
            values: Array.isArray(answer) ? answer : [],
          });
          break;
        }
        case "consoleResult":
          out.result = e.value;
          out.status = e.value.status;
          out.more = e.value.more;
          out.error = e.value.error;
          break;
        case "error":
          out.status = "died";
          out.error = e.value.message;
          break;
      }
    }
  } finally {
    h.signal?.removeEventListener("abort", onAbort);
  }
  return out;
}

/** Completions for `text` (the console's input up to the cursor) from the
 * caller's live console of the program (feature "script-completion"). */
export function completeConsole(rk: Revkit, programId: string, text: string, limit = 200): Promise<CompleteConsoleResponse> {
  return rk.scripts.completeConsole({ programId, text, limit });
}
