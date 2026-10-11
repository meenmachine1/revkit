// Type archives and categories through the TypeScript client (api_minor 35,
// feature "type-archive"; docs/types.md#type-archives): the import plan's
// archive defaults and category bodies without a daemon, then against
// `rk-daemon --backend image` the corpus's debug cJSON exported, imported
// into its stripped twin, exported again byte for byte, imported again
// (nothing to do), and its types filed under a category.
//
//   RK_DAEMON=../../build/tools/rk-daemon/rk-daemon npx tsx test/archives.ts
import { createConnectTransport } from "@connectrpc/connect-node";
import { create } from "@bufbuild/protobuf";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import assert from "node:assert/strict";

import {
  createRevkit, exportTypeArchive, importTypeArchive, normalizeCategory, parseTypeArchive, ParseCResponseSchema,
  ProvenanceKind, setTypeCategory, sidecarHeaderName, TYPE_ARCHIVE_FEATURE, typeArchiveImportBodies,
  typeCategoryBodies, TypeArchiveScope, TypeKind, TypeSource, headerImportBodies,
} from "../src/index";

const bin = process.env.RK_DAEMON ?? path.resolve(import.meta.dirname, "../../../build/tools/rk-daemon/rk-daemon");
const corpus = process.env.REVKIT_CORPUS ?? path.resolve(import.meta.dirname, "../../../out/corpus");
const dir = mkdtempSync(path.join(tmpdir(), "rk-ts-archives-"));

function plans() {
  assert.equal(normalizeCategory("/net/http/"), "/net/http");
  assert.equal(normalizeCategory("/"), "");
  assert.equal(normalizeCategory("net"), null);
  assert.equal(normalizeCategory("/a//b"), null);
  assert.equal(normalizeCategory("/a/../b"), null);
  const bodies = typeCategoryBodies(["struct a", "typedef b"], "/x");
  assert.deepEqual(bodies.map((b) => b.kind.case === "typeCategory" ? `${b.kind.value.namedKey}@${b.kind.value.path}` : ""),
    ["struct a@/x", "typedef b@/x"]);
  assert.equal(sidecarHeaderName('{"header": "cjson.h"}'), "cjson.h");
  assert.equal(sidecarHeaderName("not json"), undefined);

  const idx = (value: number) => ({ kind: { case: "assertionIndex" as const, value } });
  const parsed = create(ParseCResponseSchema, {
    nodes: [
      { kind: TypeKind.INT, size: 4n },
      { kind: TypeKind.STRUCT, name: "a", size: 4n, fields: [{ name: "x", type: idx(0) }] },
      { kind: TypeKind.TYPEDEF, name: "size_t", target: { kind: { case: "hash", value: "ff" } } },
      { kind: TypeKind.TYPEDEF, name: "same", target: idx(0) },
    ],
    named: [
      { key: "struct a", index: 1, hash: "a1", existingHash: "", category: "/a.h" },
      { key: "typedef size_t", index: 2, hash: "s1", existingHash: "s1", existingLibrary: true, category: "/stddef.h" },
      { key: "typedef same", index: 3, hash: "m1", existingHash: "m1", category: "/m.h", existingCategory: "/old" },
    ],
  });
  const kinds = (bs: ReturnType<typeof headerImportBodies>) =>
    bs.map((b) => b.kind.case === "typeCategory" ? `cat ${b.kind.value.namedKey} ${b.kind.value.path}` : b.kind.case);
  // A header: the new type, filed under its header.
  assert.deepEqual(kinds(headerImportBodies(parsed)), ["defineType", "defineType", "bindTypeName", "cat struct a /a.h"]);
  assert.deepEqual(kinds(headerImportBodies(parsed, { categories: "none" })), ["defineType", "defineType", "bindTypeName"]);
  // An archive: the library's definition imported too; every category as the archive says.
  assert.deepEqual(kinds(typeArchiveImportBodies(parsed)), [
    "defineType", "defineType", "defineType", "bindTypeName", "bindTypeName",
    "cat struct a /a.h", "cat typedef size_t /stddef.h", "cat typedef same /m.h",
  ]);
  // A renamed type is filed under its new name.
  assert.deepEqual(kinds(headerImportBodies(parsed, { keys: ["struct a"], rename: { "struct a": "b" } })).at(-1), "cat struct b /a.h");
  console.log("archives: import plans and categories");
}

async function main() {
  plans();
  const debugPath = path.join(corpus, "elf-x86_64/gcc-O2/debug/cjson");
  const strippedPath = path.join(corpus, "elf-x86_64/gcc-O2/stripped/cjson");
  if (!existsSync(debugPath) || !existsSync(strippedPath) || !existsSync(bin)) {
    console.log("archives: corpus or daemon not built; skipping the daemon part");
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
    assert.ok(info.apiMinor >= 35 && info.features.includes(TYPE_ARCHIVE_FEATURE), "the daemon has feature type-archive");
    const load = async (file: string, name: string) => (await rk.projects.importProgram({
      projectId: "default", name, source: { case: "content", value: readFileSync(file) },
    })).program!.programId;
    const debug = await load(debugPath, "cjson-debug");
    const stripped = await load(strippedPath, "cjson");

    const a = await exportTypeArchive(rk, { programId: debug, scope: TypeArchiveScope.ALL });
    assert.equal(a.headerName, "cjson-debug.h");
    assert.equal(a.mismatches, 0);
    assert.ok(a.header.includes("_Static_assert(sizeof(struct cJSON) == 64"), a.header);
    const sidecar = JSON.parse(a.sidecar);
    assert.equal(sidecar.format, "revkit-type-archive");
    assert.equal(sidecar.provenance.origin, "cjson-debug");
    assert.equal(sidecar.types.find((t: { key: string }) => t.key === "struct cJSON").category, "/cJSON.h");

    const parsed = await parseTypeArchive(rk, stripped, { header: a.header, sidecar: a.sidecar });
    assert.equal(parsed.archive?.verified, parsed.archive?.types);
    assert.equal(parsed.archive?.headerChanged, false);
    const done = await importTypeArchive(rk, stripped, parsed, { reason: "ts archive test" });
    assert.ok(done && done.assertions.length > 0);
    const b = await exportTypeArchive(rk, { programId: stripped, scope: TypeArchiveScope.ALL });
    assert.equal(b.header, a.header);
    assert.equal(b.sidecar, a.sidecar);
    // Again: nothing to do.
    assert.equal(await importTypeArchive(rk, stripped, await parseTypeArchive(rk, stripped, { header: a.header, sidecar: a.sidecar })), null);
    // A tampered header is refused.
    const bad = await parseTypeArchive(rk, stripped, { header: a.header.replace("int valueint;", "long valueint;"), sidecar: a.sidecar });
    assert.ok(bad.archive!.headerChanged && bad.archive!.mismatches.length > 0);
    await assert.rejects(importTypeArchive(rk, stripped, bad), /don't parse to the sidecar's hashes/);

    // Categories: move one, list the folders, filter by one.
    await setTypeCategory(rk, stripped, ["struct cJSON", "typedef cJSON"], "/json/core", { kind: ProvenanceKind.USER, id: "ts" });
    const found = await rk.queries.findTypes({ programId: stripped, category: "/json", includeCategories: true, sources: [TypeSource.PROGRAM] });
    assert.deepEqual(found.types.map((t) => `${t.name}@${t.category}`).sort(), ["cJSON@/json/core", "cJSON@/json/core"]);
    const folders = new Map(found.categories.map((c) => [c.path, c.types]));
    assert.equal(folders.get("/json/core"), 2);
    assert.equal(folders.get("/json"), 0);
    assert.ok((folders.get("/cJSON.h") ?? 0) > 0);
    const byCategory = await exportTypeArchive(rk, { programId: stripped, category: "/json" });
    assert.ok(byCategory.archive!.types.some((t) => t.key === "struct cJSON" && t.category === "/json/core"));
    console.log("archives: export, import into the stripped twin, byte-identical export, categories");
  } finally {
    daemon.kill();
    rmSync(dir, { recursive: true, force: true });
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
