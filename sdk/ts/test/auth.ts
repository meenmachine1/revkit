// The TypeScript client against an rk-daemon with authentication and TLS
// (docs/security.md): starts `rk-daemon --backend fake` with its own
// credential file and a self-signed certificate, issues tokens with
// `rk-daemon token create`, and checks every protocol over TLS with the
// certificate pinned, server-stamped provenance and role denial.
//
//   RK_DAEMON=../../build/tools/rk-daemon/rk-daemon npm run smoke:auth
import { ConnectError, Code } from "@connectrpc/connect";
import { execFileSync, spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import assert from "node:assert/strict";

import { CommentKind, createRevkit, PrincipalKind, ProvenanceKind } from "../src/index";
import { fetchCertificate, nodeTransport } from "../node/index";

const bin = process.env.RK_DAEMON ?? path.resolve(import.meta.dirname, "../../../build/tools/rk-daemon/rk-daemon");
const dir = mkdtempSync(path.join(tmpdir(), "rk-ts-auth-"));
const auth = ["--auth-file", path.join(dir, "auth.db")];
const program = "demo/hello";

async function main() {
  const editor = execFileSync(bin, ["token", "create", "--name", "ts-bot", "--role", "editor", ...auth], { encoding: "utf8" }).trim();
  const viewer = execFileSync(bin, ["token", "create", "--name", "ts-view", "--role", "viewer", ...auth], { encoding: "utf8" }).trim();
  const ports = path.join(dir, "ports.json");
  const daemon = spawn(bin, ["--backend", "fake", "--grpc", "127.0.0.1:0", "--http", "127.0.0.1:0", "--port-file", ports,
    "--tls-self-signed", "--tls-dir", path.join(dir, "tls"), ...auth], { stdio: ["ignore", "ignore", "inherit"] });
  try {
    for (let i = 0; i < 300 && !existsSync(ports); i++) await new Promise((r) => setTimeout(r, 50));
    const { grpc, http } = JSON.parse(readFileSync(ports, "utf8"));
    const fingerprint = execFileSync(bin, ["tls", "fingerprint", "--tls-dir", path.join(dir, "tls")], { encoding: "utf8" }).trim();
    assert.equal((await fetchCertificate("127.0.0.1", http)).fingerprint256, fingerprint);

    const https = `https://127.0.0.1:${http}`;
    for (const [protocol, baseUrl] of [["connect", https], ["grpc-web", https], ["grpc", `https://127.0.0.1:${grpc}`]] as const) {
      const rk = createRevkit(await nodeTransport({ baseUrl, protocol, token: editor, fingerprint }));
      const who = await rk.auth.whoAmI({});
      assert.equal(who.identity?.kind, PrincipalKind.AGENT);
      assert.equal(who.identity?.name, "ts-bot");
      const fns = await rk.queries.listFunctions({ programId: program });
      assert.equal(fns.functions.length, 4);
      const r = await rk.assertions.appendAssertions({
        programId: program,
        provenance: { session: "ts-auth", reason: protocol },
        assertions: [{ body: { kind: { case: "comment", value: { address: { offset: 0x401040n }, kind: CommentKind.EOL, text: protocol } } } }],
      });
      assert.equal(r.assertions[0].provenance?.kind, ProvenanceKind.AGENT);
      assert.equal(r.assertions[0].provenance?.id, "ts-bot");
      console.log(`${protocol}: agent:ts-bot over TLS (pinned), ${fns.functions.length} functions`);
    }

    const view = createRevkit(await nodeTransport({ baseUrl: https, token: viewer, fingerprint }));
    await assert.rejects(view.assertions.appendAssertions({ programId: program, assertions: [] }),
      (e: unknown) => e instanceof ConnectError && e.code === Code.PermissionDenied);
    const anon = createRevkit(await nodeTransport({ baseUrl: https, token: "", fingerprint }));
    await assert.rejects(anon.queries.listFunctions({ programId: program }),
      (e: unknown) => e instanceof ConnectError && e.code === Code.Unauthenticated);
    await assert.rejects(nodeTransport({ baseUrl: https, fingerprint: "00".repeat(32) }), /not the pinned/);
    console.log("roles, anonymous callers and a wrong pin are refused");
  } finally {
    daemon.kill("SIGTERM");
    rmSync(dir, { recursive: true, force: true });
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
