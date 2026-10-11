// Receives autobench results from pages Playwright can't drive (the Tauri
// shell): POST /results?label=<label> writes bench/raw/autobench-<label>.json.
//
//   tsx bench/sink.ts [--port 8790] [--dir bench/raw]

import { createServer } from "node:http";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

const args = new Map<string, string>();
for (let i = 2; i < process.argv.length; i += 2) args.set(process.argv[i].replace(/^--/, ""), process.argv[i + 1]);
const port = Number(args.get("port") ?? 8790);
const dir = args.get("dir") ?? "bench/raw";

createServer(async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "*");
  if (req.method === "OPTIONS") return res.writeHead(204).end();
  const url = new URL(req.url ?? "/", "http://x");
  if (req.method !== "POST" || url.pathname !== "/results") return res.writeHead(404).end();
  const label = (url.searchParams.get("label") ?? "unnamed").replace(/[^\w.-]/g, "_");
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  await mkdir(dir, { recursive: true });
  const file = path.join(dir, `autobench-${label}.json`);
  await writeFile(file, Buffer.concat(chunks));
  console.log(`wrote ${file}`);
  res.writeHead(204).end();
}).listen(port, "127.0.0.1", () => console.log(`bench sink on http://127.0.0.1:${port}`));
