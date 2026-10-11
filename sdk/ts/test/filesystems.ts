// Container file systems through the TypeScript client (api_minor 48,
// feature "filesystems"): path helpers without a daemon, then against
// `rk-daemon --backend image` a zip holding an ELF and a tar.gz (made with
// Python's zipfile and tarfile) opened from bytes, listed with guesses,
// read across layers, described, imported (one, and a batch preview).
//
//   RK_DAEMON=../../build/tools/rk-daemon/rk-daemon npx tsx test/filesystems.ts
import { createConnectTransport } from "@connectrpc/connect-node";
import { execFileSync, spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import assert from "node:assert/strict";

import {
  createRevkit, displayPath, encodeName, FileSystemEntryKind, FILESYSTEMS_FEATURE, isBrowsable, isProgram, joinPath,
  looksLikeContainer, openFileSystem, parentPath, pathLayers,
} from "../src/index";

const bin = process.env.RK_DAEMON ?? path.resolve(import.meta.dirname, "../../../build/tools/rk-daemon/rk-daemon");
const dir = mkdtempSync(path.join(tmpdir(), "rk-ts-fs-"));

function pure() {
  assert.equal(encodeName("a!b%c/d"), "a%21b%25c%2Fd");
  assert.equal(displayPath("/a%21b!/c%2Fd"), "/a!b!/c/d");
  assert.equal(displayPath("/caf%C3%A9"), "/café");
  assert.deepEqual(pathLayers("/x.zip!/a/b"), ["/x.zip", "/a/b"]);
  assert.equal(joinPath("/x.zip!/", "a!b"), "/x.zip!/a%21b");
  assert.equal(joinPath("/d", "e"), "/d/e");
  assert.equal(parentPath("/a/b"), "/a");
  assert.equal(parentPath("/a"), "/");
  assert.equal(parentPath("/"), "/");
  assert.equal(parentPath("/x.zip!/a"), "/x.zip!/");
  assert.equal(parentPath("/x.zip!/"), "/x.zip");
  assert.equal(looksLikeContainer(new Uint8Array([0x50, 0x4b, 3, 4])), "zip");
  assert.equal(looksLikeContainer(new Uint8Array([0x7f, 0x45, 0x4c, 0x46])), "");
}

const MAKE = String.raw`
import io, sys, tarfile, zipfile
exe = open('/bin/true', 'rb').read()
tgz = io.BytesIO()
with tarfile.open(fileobj=tgz, mode='w:gz') as t:
    i = tarfile.TarInfo('usr/bin/true'); i.size = len(exe); i.mode = 0o755; t.addfile(i, io.BytesIO(exe))
with zipfile.ZipFile(sys.argv[1], 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr('bin/true', exe)
    z.writestr('notes/readme.txt', 'hello\n')
    z.writestr('pkg/data.tar.gz', tgz.getvalue())
`;

async function main() {
  pure();
  const zipPath = path.join(dir, "fw.zip");
  execFileSync("python3", ["-I", "-c", MAKE, zipPath]);
  const ports = path.join(dir, "ports.json");
  const daemon = spawn(bin, ["--backend", "image", "--no-auth", "--no-web-root", "--grpc", "127.0.0.1:0", "--http", "127.0.0.1:0",
    "--port-file", ports], { stdio: ["ignore", "ignore", "inherit"] });
  try {
    for (let i = 0; i < 1200 && !existsSync(ports); i++) await new Promise((r) => setTimeout(r, 50));
    const { http } = JSON.parse(readFileSync(ports, "utf8"));
    const rk = createRevkit(createConnectTransport({ baseUrl: `http://127.0.0.1:${http}`, httpVersion: "1.1" }));
    const info = await rk.meta.getServerInfo({});
    assert.ok(info.features.includes(FILESYSTEMS_FEATURE), `${info.features}`);
    const bytes = new Uint8Array(readFileSync(zipPath));
    const fs = await openFileSystem(rk, "default", { file: bytes, name: "fw.zip" });
    try {
      assert.equal(fs.root?.format, "zip");
      const top = await fs.list("/");
      assert.deepEqual(top.entries.map((e) => e.name), ["bin", "notes", "pkg"]);
      assert.ok(top.entries.every((e) => e.kind === FileSystemEntryKind.DIRECTORY && isBrowsable(e)));
      const bins = await fs.entries("/bin");
      assert.equal(bins[0].detectedKind, "elf");
      assert.ok(isProgram(bins[0]));
      const pkg = await fs.entries("/pkg");
      assert.equal(pkg[0].containerFormat, "gzip");
      assert.ok(isBrowsable(pkg[0]));
      const inner = await fs.list(pkg[0].path);
      assert.equal(inner.layer?.format, "gzip");
      assert.equal(inner.entries[0].name, "data.tar");
      const deep = "/pkg/data.tar.gz!/data.tar!/usr/bin/true";
      assert.deepEqual(await fs.read(deep), new Uint8Array(readFileSync("/bin/true")));
      assert.deepEqual(await fs.read("/notes/readme.txt", 1, 3), new TextEncoder().encode("ell"));
      const described = await fs.info(deep, true);
      assert.equal(described.containerPath, "zip://fw.zip!" + deep);
      assert.equal(described.sha256.length, 64);
      const preview = await fs.import(["/"], { recursive: true, descend: true, preview: true });
      assert.deepEqual(preview.items.filter((i) => i.action === "import").map((i) => i.path).sort(), ["/bin/true", deep]);
      const done = await fs.import([deep], { options: { analyze: false } });
      assert.equal(done.imported, 1);
      assert.equal(done.items[0].program?.containerPath, "zip://fw.zip!" + deep);
      const listed = await rk.projects.listPrograms({ projectId: "default" });
      assert.ok(listed.programs.some((p) => p.containerPath === "zip://fw.zip!" + deep));
    } finally {
      await fs.close();
    }
    console.log("ts filesystems: ok");
  } finally {
    daemon.kill();
    rmSync(dir, { recursive: true, force: true });
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
