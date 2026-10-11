// Builds the publishable package into dist/ (npm pack runs this as prepack):
// ES modules bundled by esbuild, with the runtime dependencies left as
// imports, and .d.ts declarations from tsc. The UI and the tests use the
// TypeScript sources directly and need none of this.
//
//   dist/index.js   "@revkit/api"       (browsers, Tauri, Node)
//   dist/node.js    "@revkit/api/node"  (Node: TLS pinning, gRPC; needs @connectrpc/connect-node)
//   dist/types/     declarations (moduleResolution "bundler" or "node16"/"nodenext" with a bundler)
import { build } from "esbuild";
import { execFileSync } from "node:child_process";
import { rmSync } from "node:fs";

rmSync("dist", { recursive: true, force: true });
await build({
  entryPoints: { index: "src/index.ts", node: "node/index.ts" },
  outdir: "dist",
  bundle: true,
  splitting: true,
  format: "esm",
  platform: "neutral",
  target: "es2022",
  external: ["@bufbuild/*", "@connectrpc/*", "node:*"],
  chunkNames: "chunks/[name]-[hash]",
  legalComments: "none",
  logLevel: "warning",
});
execFileSync("node_modules/.bin/tsc", ["-p", "tsconfig.build.json"], { stdio: "inherit" });
console.log("sdk/ts: built dist/");
