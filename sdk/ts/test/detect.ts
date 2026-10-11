// Raw layout detection through the TypeScript client (feature "raw-detect"),
// against an rk-daemon on the image backend, over Connect as a browser
// speaks it: what is no program is refused with the reason, the daemon's
// own code (cut out of its executable, a blob with no header) is named with
// its confidence and evidence while the progress is polled, a detection is
// stopped by aborting, and a suggestion's options import as they are.
//
//   RK_DAEMON=../../build/tools/rk-daemon/rk-daemon npm run test:detect
import { Code, ConnectError } from "@connectrpc/connect";
import { createConnectTransport } from "@connectrpc/connect-node";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { closeSync, existsSync, mkdtempSync, openSync, readFileSync, readSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import assert from "node:assert/strict";

import {
  confidenceName, createRevkit, detectRawLayout, DetectConfidence, RAW_DETECT_FEATURE, RawDetectPhase, RawSegmentKind,
  type GetRawDetectProgressResponse,
} from "../src/index";

const bin = process.env.RK_DAEMON ?? path.resolve(import.meta.dirname, "../../../build/tools/rk-daemon/rk-daemon");
const dir = mkdtempSync(path.join(tmpdir(), "rk-ts-detect-"));

/** `size` bytes from the middle of an ELF64 file's .text: code with no header. */
function ownCode(file: string, size: number): Uint8Array | null {
  const fd = openSync(file, "r");
  try {
    const at = (offset: number, n: number) => {
      const b = Buffer.alloc(n);
      return readSync(fd, b, 0, n, offset) === n ? b : null;
    };
    const head = at(0, 64);
    if (!head || head.readUInt32BE(0) !== 0x7f454c46 || head[4] !== 2 || head[5] !== 1) return null;  // ELF64, little-endian
    const shoff = Number(head.readBigUInt64LE(0x28)), shentsize = head.readUInt16LE(0x3a), shnum = head.readUInt16LE(0x3c);
    const sections = at(shoff, shentsize * shnum);
    if (!sections) return null;
    const section = (i: number) => {
      const s = sections.subarray(i * shentsize, (i + 1) * shentsize);
      return { name: s.readUInt32LE(0), offset: Number(s.readBigUInt64LE(0x18)), size: Number(s.readBigUInt64LE(0x20)) };
    };
    const names = section(head.readUInt16LE(0x3e));
    const strings = at(names.offset, names.size);
    if (!strings) return null;
    for (let i = 0; i < shnum; i++) {
      const s = section(i);
      if (strings.subarray(s.name, s.name + 6).toString("latin1") !== ".text\0" || s.size < 2 * size) continue;
      const middle = (s.offset + s.size / 2) & ~0xfff;
      return at(middle, size);
    }
    return null;
  } finally {
    closeSync(fd);
  }
}

async function main() {
  const ports = path.join(dir, "ports.json");
  const daemon = spawn(bin, ["--backend", "image", "--no-auth", "--no-web-root", "--grpc", "127.0.0.1:0", "--http", "127.0.0.1:0",
    "--port-file", ports], { stdio: ["ignore", "ignore", "inherit"] });
  try {
    for (let i = 0; i < 1200 && !existsSync(ports); i++) await new Promise((r) => setTimeout(r, 50));
    const { http } = JSON.parse(readFileSync(ports, "utf8"));
    const rk = createRevkit(createConnectTransport({ baseUrl: `http://127.0.0.1:${http}`, httpVersion: "1.1" }));
    const info = await rk.meta.getServerInfo({});
    assert.ok(info.features.includes(RAW_DETECT_FEATURE), `features: ${info.features}`);
    assert.ok(info.apiMinor >= 23);

    // What is no program is refused, with the reason and the file's map.
    const noise = new Uint8Array(randomBytes(1 << 16));
    const seen: GetRawDetectProgressResponse[] = [];
    const refused = await detectRawLayout(rk, { projectId: "default", source: { case: "content", value: noise } },
      { onProgress: (p) => seen.push(p), pollMs: 5 });
    assert.equal(refused.refusal?.reason, "high-entropy");
    assert.ok(refused.refusal?.detail);
    assert.equal(refused.suggestions.length, 0);
    assert.deepEqual(refused.segments.map((s) => [s.offset, s.size, s.kind]), [[0n, 65536n, RawSegmentKind.HIGH_ENTROPY]]);
    assert.equal(refused.fileSize, 65536n);
    const text = path.join(dir, "log.txt");
    writeFileSync(text, "log line: sensor ok\r\n".repeat(4096));
    assert.equal((await detectRawLayout(rk, { projectId: "default", source: { case: "path", value: text } })).refusal?.reason, "not-code");
    assert.equal((await rk.projects.detectRawLayout({ projectId: "default", source: { case: "content", value: new Uint8Array(16) } })).refusal?.reason, "too-small");
    await assert.rejects(detectRawLayout(rk, { projectId: "default", source: { case: "path", value: path.join(dir, "missing") } }),
      (e: unknown) => e instanceof ConnectError && e.code === Code.NotFound);
    await assert.rejects(detectRawLayout(rk, { projectId: "default", source: { case: "content", value: noise }, hints: { processor: "no such processor" } }),
      (e: unknown) => e instanceof ConnectError && e.code === Code.InvalidArgument);
    console.log(`refusals: high-entropy, not-code, too-small; ${seen.length} progress reports`);

    const code = ownCode(bin, 128 << 10);
    const own = { x64: ["x86", "x86:LE:64:"], arm64: ["AARCH64", "AARCH64:LE:64:"] }[process.arch as string];
    if (!code || !own) {
      console.log("ts detect: ok (no code of a known processor to read: the suggestion checks were skipped)");
      return;
    }
    // The daemon's own code, knowing its processor: named, with its
    // confidence and evidence, while the progress is followed to the end.
    seen.length = 0;
    const r = await detectRawLayout(rk, { projectId: "default", source: { case: "content", value: code }, hints: { processor: own[0] } },
      { onProgress: (p) => seen.push(p), pollMs: 5 });
    assert.equal(r.refusal, undefined);
    const top = r.suggestions[0];
    assert.equal(top.options?.format, "raw");
    assert.ok(`${top.options?.languageId}:`.startsWith(own[1]), top.options?.languageId);
    assert.ok(top.options?.compilerSpecId);
    assert.notEqual(confidenceName(top.processorConfidence), "");
    assert.notEqual(top.baseConfidence, DetectConfidence.UNSPECIFIED);
    assert.equal(top.evidence[0]?.about, "processor");
    assert.match(top.evidence[0].text, /instructions decode/);
    assert.equal(r.segments.reduce((n, s) => n + s.size, 0n), BigInt(code.length));
    assert.ok(seen.length > 0, "no progress reported");
    const fractions = seen.filter((p) => p.progress >= 0).map((p) => p.progress);
    assert.deepEqual(fractions, [...fractions].sort((a, b) => a - b), "the fraction never goes back");
    assert.deepEqual(seen.map((p) => p.phase), seen.map((p) => p.phase).sort((a, b) => a - b), "phases in order");
    const last = await rk.projects.getRawDetectProgress({ projectId: "default", detectId: "nobody's" }).catch((e) => e);
    assert.ok(last instanceof ConnectError && last.code === Code.NotFound);
    console.log(`${top.options?.languageId} (${confidenceName(top.processorConfidence)}): ${top.evidence[0].text.slice(0, 60)}…; ${seen.length} progress reports`);

    // Every language tried, and stopped once the first candidates are in:
    // the call rejects, and the daemon says the detection was cancelled.
    const stop = new AbortController();
    let stoppedAt: GetRawDetectProgressResponse | undefined;
    const detectId = "stop-me";
    await assert.rejects(
      detectRawLayout(rk, { projectId: "default", source: { case: "content", value: code }, detectId }, {
        signal: stop.signal,
        pollMs: 5,
        onProgress: (p) => {
          if (p.candidatesDone >= 1 && !stoppedAt) {
            stoppedAt = p;
            stop.abort();
          }
        },
      }),
      (e: unknown) => e instanceof ConnectError && e.code === Code.Canceled,
    );
    assert.ok(stoppedAt && !stoppedAt.done, "it ended before it could be stopped");
    // It stops once the candidates being decoded end: about a second here,
    // several under a sanitizer.
    let after = await rk.projects.getRawDetectProgress({ projectId: "default", detectId });
    for (const end = Date.now() + 90_000; !after.done && Date.now() < end; ) {
      await new Promise((resolve) => setTimeout(resolve, 25));
      after = await rk.projects.getRawDetectProgress({ projectId: "default", detectId });
    }
    assert.ok(after.done && after.cancelled && !after.error, JSON.stringify({ done: after.done, cancelled: after.cancelled, error: after.error }));
    assert.equal(after.phase, RawDetectPhase.DONE);
    assert.ok(after.candidatesDone < after.candidatesTotal);
    // Aborted before it starts: nothing is sent.
    await assert.rejects(detectRawLayout(rk, { projectId: "default", source: { case: "content", value: code } }, { signal: stop.signal }),
      (e: unknown) => e instanceof ConnectError && e.code === Code.Canceled);
    console.log(`stopped at ${after.candidatesDone}/${after.candidatesTotal} languages`);

    // A suggestion's options are an import's, as they are. Nothing was
    // imported until now.
    assert.equal((await rk.projects.listPrograms({ projectId: "default" })).programs.length, 0);
    const imported = await rk.projects.importProgram({
      projectId: "default", name: "own-code", source: { case: "content", value: code.subarray(0, 16 << 10) }, options: top.options,
    });
    assert.equal(imported.program?.format, "raw");
    assert.equal(imported.program?.languageId, top.options?.languageId);
    console.log("ts detect: ok");
  } finally {
    daemon.kill("SIGTERM");
    rmSync(dir, { recursive: true, force: true });
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
