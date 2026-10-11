// Runs the official Connect-ES client against a live rk-daemon (started with
// --backend fake: it checks the synthetic demo program) over all
// three protocols it serves: Connect (HTTP/1.1, JSON), gRPC-web (HTTP/1.1,
// binary) and gRPC (HTTP/2, against the gRPC port when RK_GRPC_URL is set).
//
//   RK_HTTP_URL=http://127.0.0.1:50052 RK_GRPC_URL=http://127.0.0.1:50051 npm run smoke
import { createConnectTransport, createGrpcTransport, createGrpcWebTransport } from "@connectrpc/connect-node";
import assert from "node:assert/strict";

import { createRevkit, ProvenanceKind, SubscriptionService } from "../src/index";
import { createClient } from "@connectrpc/connect";

const httpUrl = process.env.RK_HTTP_URL ?? "http://127.0.0.1:50052";
const grpcUrl = process.env.RK_GRPC_URL ?? "";
const program = "demo/hello";
const checksum = 0x401040n;

async function main() {
  const transports = {
    connect: createConnectTransport({ baseUrl: httpUrl, httpVersion: "1.1" }),
    "connect+proto": createConnectTransport({ baseUrl: httpUrl, httpVersion: "1.1", useBinaryFormat: true }),
    "grpc-web": createGrpcWebTransport({ baseUrl: httpUrl, httpVersion: "1.1" }),
    ...(grpcUrl ? { grpc: createGrpcTransport({ baseUrl: grpcUrl }) } : {}),
  };

  for (const [name, transport] of Object.entries(transports)) {
    const rk = createRevkit(transport);
    const info = await rk.meta.getServerInfo({ client: "revkit-ts-smoke" });
    assert.equal(info.apiMajor, "v1");
    const fns = await rk.queries.listFunctions({ programId: program });
    assert.equal(fns.functions.length, 4);
    const fn = await rk.queries.getFunction({ programId: program, address: { offset: checksum } });
    console.log(`${name}: ${fns.functions.length} functions, revision ${fns.snapshot?.revision}, ${fn.function?.name}`);
  }

  // Server streaming over Connect: subscribe, rename, see the revision event.
  const rk = createRevkit(transports.connect);
  const abort = new AbortController();
  const subs = createClient(SubscriptionService, transports.connect);
  const stream = subs.subscribe({ projectId: "demo" }, { signal: abort.signal })[Symbol.asyncIterator]();
  const hello = await stream.next();
  assert.equal(hello.value?.event.case, "hello");
  const head = hello.value.event.value.headRevision;

  const name = `checksum_ts_${Date.now() % 100000}`;
  const appended = await rk.assertions.appendAssertions({
    programId: program,
    provenance: { kind: ProvenanceKind.AGENT, id: "ts-smoke", session: "smoke" },
    assertions: [{ body: { kind: { case: "rename", value: { target: { kind: { case: "address", value: { offset: checksum } } }, name } } } }],
  });
  assert.equal(appended.snapshot?.revision, head + 1n);

  let event;
  do event = await stream.next(); while (event.value?.event.case !== "revision");
  assert.equal(event.value.event.value.revision, head + 1n);
  console.log(`connect stream: revision ${event.value.event.value.revision}, ${event.value.event.value.invalidated.length} invalidated queries`);
  abort.abort();

  const dec = await rk.queries.decompile({ programId: program, function: { offset: 0x401010n }, options: { includeText: true } });
  assert.ok(dec.function?.text.includes(`${name}(s_hello_00402000,5)`), dec.function?.text ?? "no text");

  const reverted = await rk.assertions.revertByProvenance({
    programId: program,
    filter: { kind: ProvenanceKind.AGENT, id: "ts-smoke", session: "smoke" },
    provenance: { kind: ProvenanceKind.USER, id: "ts-smoke" },
  });
  assert.equal(reverted.retractedSeqs.length, 1);
  console.log("ts smoke: ok");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
