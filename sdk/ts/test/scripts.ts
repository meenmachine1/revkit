// Scripts the daemon runs, through the TypeScript client (ScriptService,
// api_minor 31, feature "scripts-host"; docs/scripting.md): the metadata
// helpers without a daemon, then over Connect as a browser speaks it,
// against `rk-daemon --backend image` with a hand-assembled ARM image and a
// per-user script in a temporary $XDG_CONFIG_HOME: ListScripts (shipped and
// per-user), the trust confirmation (declined, then confirmed and pinned),
// a run's output, progress and an ask_choice prompt answered, its edits as
// one revision with script provenance, and a failure's script id and line.
//
// The daemon runs scripts with $REVKIT_PYTHON (a Python with grpcio and
// protobuf) and the SDK on $PYTHONPATH, as CTest sets them:
//
//   RK_DAEMON=../../build/tools/rk-daemon/rk-daemon REVKIT_PYTHON=~/.cache/revkit/venv/bin/python \
//     PYTHONPATH=../python npx tsx test/scripts.ts
import { create } from "@bufbuild/protobuf";
import { createConnectTransport } from "@connectrpc/connect-node";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import assert from "node:assert/strict";

import {
  completeConsole, consoleRun, createRevkit, normalizeKeybinding, ProvenanceKind, runScript, SCRIPT_COMPLETION_FEATURE,
  SCRIPT_CONSOLE_FEATURE, SCRIPTS_HOST_FEATURE, scriptCategoryTree, ScriptInfoSchema, ScriptLibrary, scriptsForContext,
} from "../src/index";

const bin = process.env.RK_DAEMON ?? path.resolve(import.meta.dirname, "../../../build/tools/rk-daemon/rk-daemon");
const dir = mkdtempSync(path.join(tmpdir(), "rk-ts-scripts-"));

function words(...ws: number[]): Uint8Array {
  const out = new Uint8Array(ws.length * 4);
  const view = new DataView(out.buffer);
  ws.forEach((w, i) => view.setUint32(4 * i, w >>> 0, true));
  return out;
}

// 0x00 b main; 0x20 main: push {lr}; bl 0x40; bl 0x50; pop {pc}; 0x40, 0x50: mov r0, #n; bx lr.
const image = new Uint8Array(0x80);
image.set(words(0xea000006), 0);
image.set(words(0xe52de004, 0xeb000005, 0xeb000008, 0xe49df004), 0x20);
image.set(words(0xe3a00007, 0xe12fff1e), 0x40);
image.set(words(0xe3a00009, 0xe12fff1e), 0x50);

const NAMER = `# @category Tests/TypeScript
# @description Names the function at the cursor with a chosen prefix
# @context function
# @keybinding ctrl alt N
prefix = ask_choice("prefix", "Prefix", ["leaf", "node"], default="leaf")
monitor.set_max(3)
for i in range(3):
    monitor.increment()
f = current_function
print("naming", f.name)
rename(f, f"{prefix}_{f.entry.offset:x}")
`;

const BROKEN = `# @category Tests/TypeScript
x = 1
raise ValueError("broken on purpose")
`;

function helpers() {
  assert.equal(normalizeKeybinding("ctrl shift R"), "Ctrl+Shift+R");
  assert.equal(normalizeKeybinding("Alt-F5"), "Alt+F5");
  assert.equal(normalizeKeybinding("shift+ctrl+x"), "Ctrl+Shift+X");
  assert.equal(normalizeKeybinding("ctrl"), "");
  const s = (name: string, category: string, context: string) => create(ScriptInfoSchema, { scriptId: `user/${name}.py`, name, category, context });
  const all = [s("b", "Analysis/Naming", "program"), s("a", "Analysis/Naming", "function"), s("c", "Analysis", "selection"), s("d", "", "address")];
  const tree = scriptCategoryTree(all);
  assert.deepEqual(tree.children.map((c) => c.name), ["Analysis", "Other"]);
  assert.deepEqual(tree.children[0].scripts.map((x) => x.name), ["c"]);
  assert.deepEqual(tree.children[0].children[0].scripts.map((x) => x.name), ["a", "b"]);
  assert.equal(tree.children[0].children[0].path, "Analysis/Naming");
  assert.deepEqual(scriptsForContext(all, { function: true }).map((x) => x.name), ["a"]);
  assert.deepEqual(scriptsForContext(all, { selection: true, address: true }).map((x) => x.name), ["c", "d"]);
}

async function main() {
  helpers();
  const config = path.join(dir, "config");
  mkdirSync(path.join(config, "revkit", "scripts"), { recursive: true });
  writeFileSync(path.join(config, "revkit", "scripts", "ts_namer.py"), NAMER);
  writeFileSync(path.join(config, "revkit", "scripts", "ts_broken.py"), BROKEN);
  const ports = path.join(dir, "ports.json");
  const daemon = spawn(bin, ["--backend", "image", "--no-auth", "--grpc", "127.0.0.1:0", "--http", "127.0.0.1:0", "--port-file", ports], {
    stdio: ["ignore", "ignore", "inherit"],
    env: { ...process.env, XDG_CONFIG_HOME: config },
  });
  try {
    for (let i = 0; i < 600 && !existsSync(ports); i++) await new Promise((r) => setTimeout(r, 50));
    const { http } = JSON.parse(readFileSync(ports, "utf8"));
    const rk = createRevkit(createConnectTransport({ baseUrl: `http://127.0.0.1:${http}`, httpVersion: "1.1" }));
    const info = await rk.meta.getServerInfo({});
    assert.ok(info.apiMinor >= 31 && info.features.includes(SCRIPTS_HOST_FEATURE), `api_minor ${info.apiMinor}, features ${info.features}`);

    const imported = await rk.projects.importProgram({
      projectId: "default", name: "fw.bin", source: { case: "content", value: image },
      options: { format: "raw", languageId: "ARM:LE:32:v4t", rawPermissions: "r-x" },
    });
    const programId = imported.program!.programId;

    const list = await rk.scripts.listScripts({ projectId: "default" });
    assert.ok(list.hostEnabled, `scripts host: ${list.hostDisabledReason}`);
    assert.ok(list.python, `a Python: ${list.pythonProblem}`);
    const shipped = list.scripts.find((s) => s.scriptId === "shipped/batch_decompile.py");
    assert.ok(shipped && shipped.library === ScriptLibrary.SHIPPED && shipped.trusted && !shipped.writable);
    const namer = list.scripts.find((s) => s.scriptId === "user/ts_namer.py");
    assert.ok(namer, `scripts: ${list.scripts.map((s) => s.scriptId)}`);
    assert.equal(namer.library, ScriptLibrary.USER);
    assert.equal(namer.context, "function");
    assert.equal(namer.keybinding, "ctrl alt N");
    assert.equal(namer.trusted, false);
    assert.equal(namer.sha256.length, 64);

    // Not confirmed: declining runs nothing.
    let asked = 0;
    const declined = await runScript(rk, { scriptId: namer.scriptId, programId, address: 0x40n }, {
      onTrust: async (t) => {
        asked++;
        assert.equal(t.script?.sha256, namer.sha256);
        assert.match(t.source, /Names the function at the cursor/);
        assert.equal(t.reason, "unseen");
        return false;
      },
    });
    assert.equal(declined.status, "untrusted");
    assert.equal(asked, 1);

    // Confirmed: it runs, asks, reports progress and output, and edits once.
    const out: string[] = [];
    const progress: bigint[] = [];
    const prompts: string[] = [];
    const ran = await runScript(rk, { scriptId: namer.scriptId, programId, address: 0x40n }, {
      onTrust: async () => true,
      onOutput: (text) => out.push(text),
      onProgress: (cur, max) => progress.push(max),
      onPrompt: async (p) => {
        prompts.push(`${p.kind}:${p.name}:${p.choices.join("|")}:${p.defaultValue}`);
        return "node";
      },
    });
    assert.equal(ran.status, "ok", `${ran.error?.message} ${ran.error?.traceback}`);
    assert.deepEqual(prompts, ["choice:prefix:leaf|node:leaf"]);
    assert.ok(progress.includes(3n), `progress maxima: ${progress}`);
    assert.match(out.join(""), /naming /);
    assert.equal(ran.result!.seqs.length, 1);
    assert.equal(ran.result!.revisions.length, 1);
    const fn = await rk.queries.getFunction({ programId, address: { offset: 0x40n } });
    assert.equal(fn.function?.name, "node_40");
    const la = await rk.assertions.listAssertions({ programId, filter: { provenance: { session: ran.runId } } });
    assert.equal(la.assertions.length, 1);
    const prov = la.assertions[0].provenance!;
    assert.equal(prov.kind, ProvenanceKind.SCRIPT);
    assert.equal(prov.id, "ts_namer");
    assert.equal(prov.version, namer.sha256.slice(0, 12));
    assert.ok(prov.onBehalfOf, "who ran it");

    // Pinned now: no question the second time; the listing says so.
    const again = await runScript(rk, { scriptId: namer.scriptId, programId, address: 0x50n }, {
      onTrust: async () => assert.fail("asked again"),
      onPrompt: async () => "leaf",
    });
    assert.equal(again.status, "ok");
    assert.ok((await rk.scripts.listScripts({})).scripts.find((s) => s.scriptId === namer.scriptId)?.trusted);
    const runs = await rk.scripts.listScriptRuns({ programId });
    assert.ok(runs.runs.some((r) => r.runId === ran.runId && r.status === "ok"), "the run is listed");

    // A failure names the script and its line.
    const broken = await runScript(rk, { scriptId: "user/ts_broken.py", programId }, { onTrust: async () => true });
    assert.equal(broken.status, "error");
    assert.equal(broken.error?.scriptId, "user/ts_broken.py");
    assert.equal(broken.error?.line, 3);
    assert.match(broken.error?.message ?? "", /broken on purpose/);

    // The console (api_minor 43): a statement's output, an open block, a
    // statement's edit as one revision, completion, and Ctrl+C.
    assert.ok(info.features.includes(SCRIPT_CONSOLE_FEATURE) && info.features.includes(SCRIPT_COMPLETION_FEATURE));
    const opened = await consoleRun(rk, { programId, input: "" });
    assert.ok(opened.runId.startsWith("console-") && opened.started?.pythonVersion, `${opened.runId} ${opened.status} ${opened.error}`);
    let printed = "";
    const r1 = await consoleRun(rk, { programId, input: "answer = 6 * 7\nanswer", address: 0x50n }, { onOutput: (t) => (printed += t) });
    assert.equal(r1.status, "ok");
    assert.equal(printed, "42\n");
    assert.equal((await consoleRun(rk, { programId, input: "for i in range(2):" })).more, true);
    const edit = await consoleRun(rk, { programId, input: "rename(current_function, 'from_console')", address: 0x50n });
    assert.equal(edit.status, "ok", edit.error);
    assert.equal(edit.result!.seqs.length, 1);
    assert.equal((await rk.queries.getFunction({ programId, address: { offset: 0x50n } })).function?.name, "from_console");
    const c = await completeConsole(rk, programId, "answ");
    assert.deepEqual(c.completions.map((x) => x.text), ["answer"]);
    const abort = new AbortController();
    setTimeout(() => abort.abort(), 700);
    const stopped = await consoleRun(rk, { programId, input: "import time\nwhile True:\n    time.sleep(0.05)\n" }, { signal: abort.signal });
    assert.equal(stopped.status, "interrupted");
    printed = "";
    await consoleRun(rk, { programId, input: "answer" }, { onOutput: (t) => (printed += t) });
    assert.equal(printed, "42\n", "the namespace survives Ctrl+C");
    await rk.scripts.cancelScript({ runId: opened.runId });
    console.log("ts scripts ok");
  } finally {
    daemon.kill("SIGTERM");
    await new Promise((r) => daemon.once("exit", r));
    rmSync(dir, { recursive: true, force: true });
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
