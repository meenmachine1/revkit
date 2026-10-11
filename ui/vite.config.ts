import { defineConfig } from "vite";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

// The About box's version: REVKIT_BUILD_VERSION (scripts/package.sh passes
// `scripts/version.sh build`), else VERSION at the source root; and the git
// commit (REVKIT_GIT_SHA when building from a tree without .git).
const version =
  process.env.REVKIT_BUILD_VERSION || readFileSync(new URL("../VERSION", import.meta.url), "utf8").trim();
function gitSha(): string {
  if (process.env.REVKIT_GIT_SHA) return process.env.REVKIT_GIT_SHA;
  try {
    return execFileSync("git", ["rev-parse", "--short=12", "HEAD"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return "unknown";
  }
}

// `npm run dev` serves on :5173 and proxies the revkit API to a daemon
// (RK_DAEMON_URL, default http://127.0.0.1:50052), so hot reload works
// against real data without CORS.
const daemon = process.env.RK_DAEMON_URL ?? "http://127.0.0.1:50052";

export default defineConfig({
  define: { __REVKIT_VERSION__: JSON.stringify(version), __REVKIT_GIT_SHA__: JSON.stringify(gitSha()) },
  resolve: {
    alias: { "@revkit/api": fileURLToPath(new URL("../sdk/ts/src/index.ts", import.meta.url)) },
    // sdk/ts/src imports these; take them from ui/node_modules.
    dedupe: ["@bufbuild/protobuf", "@connectrpc/connect", "@connectrpc/connect-web"],
  },
  server: {
    port: 5173,
    proxy: { "^/revkit\\.v1\\.": { target: daemon, changeOrigin: false } },
  },
  build: { target: "es2022", sourcemap: true, chunkSizeWarningLimit: 1500 },
});
