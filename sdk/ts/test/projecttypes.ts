// Project-wide types and type archives through the TypeScript client
// (api_minor 52, feature "project-types"; docs/types.md#project-types):
// the setting bodies without a daemon, then against `rk-daemon --backend
// image` the corpus's debug cJSON imported twice, struct cJSON moved to the
// project and seen by both programs, copied back into one, and the archives
// listed and switched.
//
//   RK_DAEMON=../../build/tools/rk-daemon/rk-daemon npx tsx test/projecttypes.ts
import { createConnectTransport } from "@connectrpc/connect-node";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import assert from "node:assert/strict";

import {
  copyTypesToProgram, createRevkit, detachTypeArchive, listTypeArchives, moveTypesToProject, PROJECT_TYPES_FEATURE,
  ProvenanceKind, setTypeArchiveEnabled, TypeArchiveKind, typeArchiveBody, TypeSource,
} from "../src/index";

const bin = process.env.RK_DAEMON ?? path.resolve(import.meta.dirname, "../../../build/tools/rk-daemon/rk-daemon");
const corpus = process.env.REVKIT_CORPUS ?? path.resolve(import.meta.dirname, "../../../out/corpus");
const dir = mkdtempSync(path.join(tmpdir(), "rk-ts-project-types-"));
const who = { kind: ProvenanceKind.USER, id: "ts" };

async function main() {
  const off = typeArchiveBody({ name: "ghidra", enabled: false });
  assert.equal(off.kind.case, "typeArchive");
  assert.equal(off.kind.case === "typeArchive" && off.kind.value.enabled, false);
  console.log("projecttypes: setting bodies");

  const debugPath = path.join(corpus, "elf-x86_64/gcc-O2/debug/cjson");
  if (!existsSync(debugPath) || !existsSync(bin)) {
    console.log("projecttypes: corpus or daemon not built; skipping the daemon part");
    return;
  }
  const ports = path.join(dir, "ports.json");
  const daemon = spawn(bin, ["--backend", "image", "--no-auth", "--grpc", "127.0.0.1:0", "--http", "127.0.0.1:0", "--port-file", ports],
    { stdio: ["ignore", "ignore", "inherit"] });
  try {
    for (let i = 0; i < 600 && !existsSync(ports); i++) await new Promise((r) => setTimeout(r, 50));
    const { http } = JSON.parse(readFileSync(ports, "utf8"));
    const rk = createRevkit(createConnectTransport({ baseUrl: `http://127.0.0.1:${http}`, httpVersion: "1.1" }));
    const info = await rk.meta.getServerInfo({});
    assert.ok(info.apiMinor >= 52 && info.features.includes(PROJECT_TYPES_FEATURE), "the daemon has feature project-types");
    const load = async (name: string) => (await rk.projects.importProgram({
      projectId: "default", name, source: { case: "content", value: readFileSync(debugPath) },
    })).program!.programId;
    const a = await load("cjson-a");
    const b = await load("cjson-b");

    const moved = await moveTypesToProject(rk, a, ["struct cJSON"], who);
    assert.deepEqual(moved.types.map((t) => t.key), ["struct cJSON"]);
    assert.ok(moved.records > 0 && moved.retracted > 0);
    // The first program sees the project's; the second its own identical
    // definition, which the project's binding of the name makes the bound one.
    const inA = await rk.queries.findTypes({ programId: a, nameContains: "cJSON", sources: [TypeSource.PROJECT] });
    assert.ok(inA.types.some((t) => t.name === "cJSON" && t.project), "the first program sees the project's struct cJSON");
    const inB = await rk.queries.findTypes({ programId: b, nameContains: "cJSON" });
    assert.ok(inB.types.some((t) => t.name === "cJSON" && t.bound && t.hash === moved.types[0].hash));
    const copied = await copyTypesToProgram(rk, b, ["struct cJSON"], who);
    assert.equal(copied.types[0].hash, moved.types[0].hash);

    const archives = await listTypeArchives(rk, a);
    const ghidra = archives.find((x) => x.name === "ghidra");
    assert.ok(ghidra && ghidra.kind === TypeArchiveKind.GHIDRA && ghidra.enabled);
    await setTypeArchiveEnabled(rk, a, "ghidra", false, who);
    assert.equal((await listTypeArchives(rk, b)).find((x) => x.name === "ghidra")?.enabled, false);
    await detachTypeArchive(rk, a, "ghidra", who);
    assert.equal((await listTypeArchives(rk, b)).find((x) => x.name === "ghidra")?.enabled, true);
    console.log("projecttypes: move to project, copy to program, archives on and off");
  } finally {
    daemon.kill();
    rmSync(dir, { recursive: true, force: true });
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
