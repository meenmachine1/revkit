// Folders and project archives through the TypeScript client (features
// "project-folders", "project-archive"), against an rk-daemon on the image
// backend over Connect: folders by path, the tree a project window draws,
// an export collected from its stream, uploaded in pieces and imported
// into a new project, and an annotations-only archive whose binary is
// uploaded beside it.
//
//   RK_DAEMON=../../build/tools/rk-daemon/rk-daemon npx tsx test/projects.ts
import { Code, ConnectError } from "@connectrpc/connect";
import { createConnectTransport } from "@connectrpc/connect-node";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import assert from "node:assert/strict";

import {
  buildProjectTree, createRevkit, ensureFolder, exportProject, folderIdAt, folderWithin, importProjectArchive, moveToFolderPath,
  normalizeFolderPath, parentFolderPath, PROJECT_ARCHIVE_FEATURE, PROJECT_FOLDERS_FEATURE, resolveFolder, sha256Hex, undoFolderEdit,
  uploadFile, walkFolders, type ListProgramsResponse,
} from "../src/index";

const bin = process.env.RK_DAEMON ?? path.resolve(import.meta.dirname, "../../../build/tools/rk-daemon/rk-daemon");
const corpus = path.resolve(import.meta.dirname, "../../../out/corpus/elf-x86_64/gcc-O2/stripped");
const dir = mkdtempSync(path.join(tmpdir(), "rk-ts-projects-"));

function pure() {
  assert.equal(normalizeFolderPath("a//b/"), "/a/b");
  assert.equal(normalizeFolderPath(""), "/");
  assert.throws(() => normalizeFolderPath("/a/../b"));
  assert.equal(parentFolderPath("/a/b"), "/a");
  assert.equal(parentFolderPath("/a"), "/");
  const listing = {
    folders: [
      { folderId: "b", parentId: "a", name: "json", path: "/libs/json" },
      { folderId: "a", parentId: "", name: "libs", path: "/libs" },
    ],
    programs: [
      { programId: "p/z", name: "zlib", folderId: "a" },
      { programId: "p/c", name: "cjson", folderId: "b" },
      { programId: "p/x", name: "x", folderId: "gone" },
    ],
  } as unknown as ListProgramsResponse;
  const root = buildProjectTree(listing);
  assert.deepEqual(root.programs.map((p) => p.name), ["x"]);
  assert.deepEqual(walkFolders(root).map((f) => f.path), ["/libs", "/libs/json"]);
  assert.deepEqual(root.folders[0].folders[0].programs.map((p) => p.name), ["cjson"]);
  assert.equal(folderIdAt(listing.folders, "/libs/json"), "b");
  assert.equal(folderIdAt(listing.folders, "/"), "");
  assert.equal(folderIdAt(listing.folders, "/nope"), undefined);
  assert.ok(folderWithin(root, "b", "a"));
  assert.ok(!folderWithin(root, "a", "b"));
}

async function main() {
  pure();
  if (!existsSync(path.join(corpus, "cjson"))) {
    console.log("ts projects: ok (pure checks only: no corpus)");
    return;
  }
  const ports = path.join(dir, "ports.json");
  const daemon = spawn(bin, ["--backend", "image", "--no-auth", "--no-web-root", "--grpc", "127.0.0.1:0", "--http", "127.0.0.1:0",
    "--port-file", ports], { stdio: ["ignore", "ignore", "inherit"] });
  try {
    for (let i = 0; i < 1200 && !existsSync(ports); i++) await new Promise((r) => setTimeout(r, 50));
    const { http } = JSON.parse(readFileSync(ports, "utf8"));
    const rk = createRevkit(createConnectTransport({ baseUrl: `http://127.0.0.1:${http}`, httpVersion: "1.1" }));
    const info = await rk.meta.getServerInfo({});
    assert.ok(info.features.includes(PROJECT_FOLDERS_FEATURE) && info.features.includes(PROJECT_ARCHIVE_FEATURE), `${info.features}`);
    const cjsonBytes = new Uint8Array(readFileSync(path.join(corpus, "cjson")));
    const imported = await rk.projects.importProgram({ projectId: "default", source: { case: "content", value: cjsonBytes }, name: "cjson" });
    const cjson = imported.program!.programId;

    // Folders by path.
    const json = await ensureFolder(rk, "default", "/libs/json");
    assert.equal(await resolveFolder(rk, "default", "/libs/json"), json);
    assert.equal(await ensureFolder(rk, "default", "libs/json/"), json, "an existing path is reused");
    await assert.rejects(resolveFolder(rk, "default", "/nope"), (e: unknown) => e instanceof ConnectError && e.code === Code.NotFound);
    const moved = await moveToFolderPath(rk, "default", "/libs/json", { programIds: [cjson] });
    let tree = buildProjectTree(await rk.projects.listPrograms({ projectId: "default" }));
    assert.equal(walkFolders(tree).find((f) => f.path === "/libs/json")?.programs[0]?.programId, cjson);
    // Undone by project, then done again.
    await undoFolderEdit(rk, "default", moved.assertions.map((a) => a.seq));
    tree = buildProjectTree(await rk.projects.listPrograms({ projectId: "default" }));
    assert.equal(tree.programs[0]?.programId, cjson);
    await moveToFolderPath(rk, "default", "/libs/json", { programIds: [cjson] });

    // Export, upload in small pieces, import into a new project.
    let seen = 0;
    const full = await exportProject(rk, { projectId: "default" }, { onBytes: (n) => (seen = n) });
    assert.equal(full.fileName, "default.rkproj");
    assert.equal(seen, full.data.length);
    assert.equal(full.manifest?.programs[0]?.folder, "/libs/json");
    const pieces: number[] = [];
    const id = await uploadFile(rk, new Blob([full.data as Uint8Array<ArrayBuffer>]), { chunkBytes: 8 << 10, onProgress: (s) => pieces.push(s) });
    assert.ok(pieces.length > 1 && pieces.at(-1) === full.data.length);
    const { response } = await importProjectArchive(rk, null, { uploadId: id, newProjectName: "copy" });
    assert.equal(response.project?.projectId, "copy");
    const copy = await rk.projects.listPrograms({ projectId: "copy" });
    assert.deepEqual(copy.programs.map((p) => [p.name, p.folderPath]), [["cjson", "/libs/json"]]);

    // Annotations only: the binary goes up beside the archive.
    const ann = await exportProject(rk, { projectId: "default", programIds: [cjson], annotationsOnly: true });
    assert.ok(ann.data.length < full.data.length);
    const inspected = await importProjectArchive(rk, ann.data, { inspectOnly: true });
    assert.equal(inspected.response.programs[0]?.binarySource, "");
    assert.equal(inspected.response.programs[0]?.sha256, await sha256Hex(cjsonBytes));
    await assert.rejects(importProjectArchive(rk, null, { uploadId: inspected.uploadId }),
      (e: unknown) => e instanceof ConnectError && e.code === Code.FailedPrecondition);
    const done = await importProjectArchive(rk, null, { uploadId: inspected.uploadId, binaries: [cjsonBytes], newProjectName: "ann" });
    assert.equal(done.response.programs[0]?.binarySource, "upload");
    assert.equal((await rk.projects.listPrograms({ projectId: "ann" })).programs[0]?.folderPath, "/libs/json");
    console.log(`ts projects: ok (archive ${full.data.length} bytes, annotations ${ann.data.length})`);
  } finally {
    daemon.kill();
    rmSync(dir, { recursive: true, force: true });
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
