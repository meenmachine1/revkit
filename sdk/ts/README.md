# @revkit/api

TypeScript client for the revkit API (`proto/revkit/v1`): Connect-ES
clients for every service, over Connect or gRPC-web in browsers and Tauri,
and Connect, gRPC-web or gRPC over TLS in Node.

```ts
import { createRevkit, connectTransport } from "@revkit/api";

const rk = createRevkit(connectTransport("http://127.0.0.1:50052", true));
const info = await rk.meta.getServerInfo({});
console.log(info.serverVersion, info.features);
```

In Node, against a daemon with accounts and TLS (install
`@connectrpc/connect-node` too):

```ts
import { createRevkit } from "@revkit/api";
import { nodeTransport } from "@revkit/api/node";

const rk = createRevkit(await nodeTransport({ baseUrl: "https://host:50052", token: process.env.RK_TOKEN }));
```

For a file that isn't ELF or PE (raw firmware), `detectRawLayout` asks the
daemon what a raw import needs, follows its progress, and stops it when the
signal aborts (feature `raw-detect`):

```ts
import { confidenceName, detectRawLayout } from "@revkit/api";

const r = await detectRawLayout(rk, { projectId: "default", source: { case: "content", value: bytes } },
  { onProgress: (p) => console.log(p.message), signal: abort.signal });
if (r.refusal) console.log(r.refusal.reason, r.refusal.detail);       // suggestions are then its closest guesses
for (const s of r.suggestions) console.log(s.options?.languageId, confidenceName(s.processorConfidence), s.evidence[0]?.text);
// Once the user agrees: rk.projects.importProgram({ projectId, source, options: r.suggestions[0].options })
```

The package is ES modules with `.d.ts` declarations. It is built from the
sources here by `npm pack` (`node build.mjs`: esbuild and tsc); within the
revkit tree the UI and the tests use `src/` directly. API reference:
[`docs/api.md`](../../docs/api.md); authentication: `docs/security.md`.
