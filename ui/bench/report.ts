// Merge raw runs into bench/results.json and print a markdown summary.
//
//   tsx bench/report.ts [--json bench/results.json] bench/raw/docker.json bench/raw/autobench-*.json
//
// Playwright runs (bench/run.ts) hold several engine/dpr runs; autobench files
// (Tauri shell) hold one. The markdown goes to stdout; RESULTS.md wraps it
// with the machine description and the analysis.

import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { execSync } from "node:child_process";

interface Dist {
  mean: number;
  median: number;
  p95: number;
  p99: number;
  max: number;
}

interface Row {
  engine: string;
  version: string;
  where: string;
  dpr: number;
  painter: string;
  scenario: string;
  nominalIntervalMs: number;
  delta: Dist;
  cost: Dist;
  render: Dist;
  droppedPct: number;
  blankFramePct: number;
  staleFramePct: number;
  staleLagMedianMs: number;
  fetchMedianMs: number;
  longTasks: number | null;
  jumpLatencyMedianMs?: number;
  jumpLatencyP95Ms?: number;
  loadavg1?: number;
  /** Set on aggregated rows: number of repeated runs and range of their medians. */
  runs?: number;
  medianRange?: [number, number];
  droppedRange?: [number, number];
}

const med = (xs: number[]) => {
  const s = [...xs].sort((a, b) => a - b);
  return s.length % 2 ? s[(s.length - 1) / 2] : (s[s.length / 2 - 1] + s[s.length / 2]) / 2;
};
const medDist = (ds: Dist[]): Dist => ({
  mean: med(ds.map((d) => d.mean)),
  median: med(ds.map((d) => d.median)),
  p95: med(ds.map((d) => d.p95)),
  p99: med(ds.map((d) => d.p99)),
  max: Math.max(...ds.map((d) => d.max)),
});

/** Repeated runs of the same configuration: median of each statistic across
 * runs, plus the range of the per-run medians and drop rates. */
function aggregate(rs: Row[]): Row {
  if (rs.length === 1) return { ...rs[0], runs: 1 };
  const r0 = rs[0];
  const dm = rs.map((r) => r.delta.median);
  const dr = rs.map((r) => r.droppedPct);
  const opt = (xs: (number | undefined)[]) => (xs.every((x) => x !== undefined) ? med(xs as number[]) : undefined);
  return {
    ...r0,
    delta: medDist(rs.map((r) => r.delta)),
    cost: medDist(rs.map((r) => r.cost)),
    render: medDist(rs.map((r) => r.render)),
    droppedPct: med(dr),
    blankFramePct: med(rs.map((r) => r.blankFramePct)),
    staleFramePct: med(rs.map((r) => r.staleFramePct)),
    staleLagMedianMs: med(rs.map((r) => r.staleLagMedianMs)),
    fetchMedianMs: med(rs.map((r) => r.fetchMedianMs)),
    longTasks: r0.longTasks === null ? null : med(rs.map((r) => r.longTasks ?? 0)),
    jumpLatencyMedianMs: opt(rs.map((r) => r.jumpLatencyMedianMs)),
    jumpLatencyP95Ms: opt(rs.map((r) => r.jumpLatencyP95Ms)),
    loadavg1: opt(rs.map((r) => r.loadavg1)),
    runs: rs.length,
    medianRange: [Math.min(...dm), Math.max(...dm)],
    droppedRange: [Math.min(...dr), Math.max(...dr)],
  };
}

const pick = (d: Dist): Dist => ({ mean: d.mean, median: d.median, p95: d.p95, p99: d.p99, max: d.max });
/** Frames actually produced per second: 1000 / mean frame interval. */
const fps = (r: Row) => (r.delta.mean > 0 ? 1000 / r.delta.mean : 0);

function rowsFrom(file: string, doc: any): Row[] {
  const out: Row[] = [];
  const runs = doc.runs ?? [
    {
      engine:
        doc.label
          ?.replace(/-dpr\d$/, "")
          .replace(/-r\d+$/, "")
          .replace(/-(atlas|rowcache)$/, "") ?? "autobench",
      // WebKitGTK freezes its UA string; the version comes from webkit://gpu.
      version: doc.label?.startsWith("tauri-webkitgtk") ? (process.env.RK_TAURI_VERSION ?? "WebKitGTK 2.52.6 / Tauri 2.12.1") : "",
      dpr: doc.env?.devicePixelRatio,
      // The Tauri shell as shipped may have fallen back to a DPR 1 canvas.
      where: doc.probe && doc.probe.renderDpr !== doc.probe.nativeDpr ? `host Xvfb, canvas at DPR ${doc.probe.renderDpr}` : "host Xvfb",
      ...doc,
    },
  ];
  for (const r of runs) {
    for (const s of r.results ?? []) {
      out.push({
        engine: r.engine,
        version: r.version,
        where: r.where ?? doc.host ?? (doc.machine?.inDocker ? "docker" : "host"),
        dpr: r.dpr ?? r.env?.devicePixelRatio,
        painter: r.env?.painter ?? "direct",
        scenario: s.id,
        nominalIntervalMs: s.nominalIntervalMs,
        delta: pick(s.delta),
        cost: pick(s.cost),
        render: pick(s.render),
        droppedPct: s.droppedPct,
        blankFramePct: s.blankFramePct,
        staleFramePct: s.staleFramePct,
        staleLagMedianMs: s.staleLagMs?.median ?? 0,
        fetchMedianMs: s.fetch?.latency?.median ?? s.fetch?.meanMs ?? 0,
        longTasks: s.longTasks?.supported ? s.longTasks.count : null,
        jumpLatencyMedianMs: s.jumps?.latency?.median,
        jumpLatencyP95Ms: s.jumps?.latency?.p95,
        loadavg1: r.loadavg?.[0],
      });
    }
  }
  void file;
  return out;
}

/** Gate: median frame interval within budget. On vsync-capped engines the
 * interval can't go below the engine's idle cadence, so "on every vsync" is
 * median <= 1.05 x idle interval; uncapped runs must be < 16 ms outright. */
function passes(r: Row): boolean {
  const capped = r.nominalIntervalMs > 10;
  return capped ? r.delta.median <= Math.max(16.7, r.nominalIntervalMs) * 1.05 : r.delta.median < 16;
}

const f1 = (x: number) => (x >= 100 ? x.toFixed(0) : x.toFixed(1));
const tri = (d: Dist) => `${f1(d.median)} / ${f1(d.p95)} / ${f1(d.p99)}`;

function machine() {
  let gpu = "unknown";
  try {
    gpu = execSync("nvidia-smi --query-gpu=name,driver_version --format=csv,noheader", { encoding: "utf8" }).trim();
  } catch {
    /* no NVIDIA tools */
  }
  return {
    cpu: os.cpus()[0]?.model,
    logicalCpus: os.cpus().length,
    memGB: Math.round(os.totalmem() / 2 ** 30),
    gpu,
    os: `${os.type()} ${os.release()}`,
    note: process.env.RK_BENCH_NOTE ?? "Shared host (other agents' builds may run; load average is recorded per run). Docker runs had no GPU; host Chrome 'gpu' configs and WebKitGTK gpu-shm used the GPU.",
  };
}

async function main() {
  let files = process.argv.slice(2);
  let jsonOut = "bench/results.json";
  const j = files.indexOf("--json");
  if (j >= 0) {
    jsonOut = files[j + 1];
    files = files.filter((_, i) => i !== j && i !== j + 1);
  }
  const rows: Row[] = [];
  const sources: unknown[] = [];
  for (const f of files) {
    const doc = JSON.parse(await readFile(f, "utf8"));
    rows.push(...rowsFrom(f, doc));
    sources.push({
      file: path.basename(f),
      generatedAt: doc.generatedAt,
      host: doc.host,
      machine: doc.machine,
      query: doc.query,
      runs: (doc.runs ?? [doc]).map((r: any) => ({
        engine: r.engine ?? doc.label,
        version: r.version,
        dpr: r.dpr ?? r.env?.devicePixelRatio,
        gpuStatus: r.gpuStatus,
        env: r.env,
        loadavg: r.loadavg,
      })),
    });
  }

  // Aggregate repeated runs of the same configuration and scenario.
  const byScenario = new Map<string, Row[]>();
  for (const r of rows) {
    const k = `${r.where}|${r.engine}|${r.dpr}|${r.painter}|${r.scenario}`;
    if (!byScenario.has(k)) byScenario.set(k, []);
    byScenario.get(k)!.push(r);
  }
  const agg = [...byScenario.values()].map(aggregate);
  // One record per line: compact, but still diffable.
  const lines = (xs: unknown[]) => "[\n" + xs.map((x) => "  " + JSON.stringify(x)).join(",\n") + "\n]";
  await writeFile(
    jsonOut,
    `{\n"generatedAt": ${JSON.stringify(new Date().toISOString())},\n"method": "see bench/RESULTS.md",\n` +
      `"machine": ${JSON.stringify(machine())},\n` +
      `"aggregated": ${lines(agg)},\n"sources": ${lines(sources)},\n"rows": ${lines(rows)}\n}\n`,
  );

  const key = (r: Row) => `${r.where}|${r.engine}|${r.dpr}|${r.painter}`;
  const groups = new Map<string, Row[]>();
  for (const r of agg) {
    const k = key(r);
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k)!.push(r);
  }

  const md: string[] = [];
  md.push("| Where | Engine | DPR | Painter | Runs | Gate | Worst-scenario median frame (ms) | Worst p95 | Worst p99 | Lowest fps | Max dropped | Main-thread cost median (worst) | Control: flat fill median frame |");
  md.push("|---|---|---|---|---|---|---|---|---|---|---|---|---|");
  for (const gAll of groups.values()) {
    const g = gAll.filter((r) => r.scenario !== "fill-baseline");
    const base = gAll.find((r) => r.scenario === "fill-baseline");
    const r0 = g[0];
    const ok = g.every(passes);
    const worst = (fn: (r: Row) => number) => Math.max(...g.map(fn));
    md.push(
      `| ${r0.where} | ${r0.engine} ${r0.version} | ${r0.dpr} | ${r0.painter} | ${r0.runs} | ${ok ? "**pass**" : "**FAIL**"} | ${f1(worst((r) => r.delta.median))} | ${f1(worst((r) => r.delta.p95))} | ${f1(worst((r) => r.delta.p99))} | ${Math.min(...g.map(fps)).toFixed(0)} | ${worst((r) => r.droppedPct).toFixed(1)}% | ${f1(worst((r) => r.cost.median))} | ${base ? f1(base.delta.median) : "n/a"} |`,
    );
  }
  md.push("");

  // Painter comparison where more than one painter ran for the same engine.
  const painters = [...new Set(agg.map((r) => r.painter))];
  if (painters.length > 1) {
    const cmpScen = ["steady-12000", "random-jumps", "hover-scroll"];
    md.push("##### Painter comparison (frame median / main-thread cost median / JS render median, ms)");
    md.push("");
    md.push(`| Where | Engine | DPR | Scenario | ${painters.join(" | ")} |`);
    md.push(`|---|---|---|---|${painters.map(() => "---").join("|")}|`);
    const cfgs = new Map<string, Row[]>();
    for (const r of agg) {
      const k = `${r.where}|${r.engine}|${r.dpr}`;
      if (!cfgs.has(k)) cfgs.set(k, []);
      cfgs.get(k)!.push(r);
    }
    for (const rs of cfgs.values()) {
      if (new Set(rs.map((r) => r.painter)).size < 2) continue;
      for (const sc of cmpScen) {
        const cells = painters.map((p) => {
          const r = rs.find((x) => x.painter === p && x.scenario === sc);
          return r ? `${f1(r.delta.median)} / ${f1(r.cost.median)} / ${f1(r.render.median)}${r.droppedPct >= 1 ? ` (${r.droppedPct.toFixed(0)}% dropped)` : ""}` : "";
        });
        md.push(`| ${rs[0].where} | ${rs[0].engine} | ${rs[0].dpr} | ${sc} | ${cells.join(" | ")} |`);
      }
    }
    md.push("");
  }

  md.push("### Per-scenario detail");
  md.push("");
  for (const g of groups.values()) {
    const r0 = g[0];
    md.push(`#### ${r0.engine} ${r0.version}, DPR ${r0.dpr}, ${r0.painter} painter (${r0.where}, ${r0.runs} run${r0.runs === 1 ? "" : "s"}, idle interval ${r0.nominalIntervalMs} ms)`);
    md.push("");
    md.push("| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |");
    md.push("|---|---|---|---|---|---|---|---|---|---|");
    for (const r of g) {
      const extra = r.jumpLatencyMedianMs !== undefined ? ` (jump→filled ${f1(r.jumpLatencyMedianMs)}/${f1(r.jumpLatencyP95Ms!)} ms)` : "";
      md.push(
        `| ${r.scenario}${extra} | ${tri(r.delta)}${r.medianRange && r.runs! > 1 ? ` (medians ${f1(r.medianRange[0])}–${f1(r.medianRange[1])})` : ""} | ${fps(r).toFixed(0)} | ${tri(r.cost)} | ${f1(r.render.median)} / ${f1(r.render.p95)} | ${r.droppedPct.toFixed(1)}%${r.droppedRange && r.runs! > 1 ? ` (${r.droppedRange[0].toFixed(1)}–${r.droppedRange[1].toFixed(1)})` : ""} | ${r.blankFramePct.toFixed(1)}% | ${r.staleFramePct.toFixed(1)}%${r.staleFramePct ? ` (${f1(r.staleLagMedianMs)} ms)` : ""} | ${f1(r.fetchMedianMs)} ms | ${r.longTasks ?? "n/a"} |`,
      );
    }
    md.push("");
  }
  console.log(md.join("\n"));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
