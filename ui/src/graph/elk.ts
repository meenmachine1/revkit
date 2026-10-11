// Layered graph layout with ELK (Eclipse Layout Kernel, elkjs, EPL-2.0):
// Sugiyama-style layering, crossing minimization, Brandes-Köpf node
// placement and orthogonal edge routing, in a web worker so a 2,000-block
// function lays out without blocking the page.

import ELK, { type ElkExtendedEdge, type ElkNode } from "elkjs/lib/elk-api.js";
import workerUrl from "elkjs/lib/elk-worker.min.js?url";

export interface LayoutNode {
  id: string;
  width: number;
  height: number;
}

export interface LayoutEdge {
  id: string;
  from: string;
  to: string;
}

export interface Placed {
  nodes: Map<string, { x: number; y: number; w: number; h: number }>;
  /** Each edge's polyline (start, bends, end). */
  edges: Map<string, { x: number; y: number }[]>;
  width: number;
  height: number;
  ms: number;
}

let elk: InstanceType<typeof ELK> | null = null;

function engine() {
  elk ??= new ELK({ workerFactory: () => new Worker(workerUrl) });
  return elk;
}

export async function layout(nodes: LayoutNode[], edges: LayoutEdge[]): Promise<Placed> {
  const t0 = performance.now();
  const big = nodes.length > 400;
  const graph: ElkNode = {
    id: "root",
    layoutOptions: {
      "elk.algorithm": "layered",
      "elk.direction": "DOWN",
      "elk.edgeRouting": "ORTHOGONAL",
      "elk.layered.nodePlacement.strategy": "BRANDES_KOEPF",
      "elk.layered.cycleBreaking.strategy": "DEPTH_FIRST",
      "elk.spacing.nodeNode": "28",
      "elk.layered.spacing.nodeNodeBetweenLayers": "36",
      "elk.layered.spacing.edgeNodeBetweenLayers": "14",
      "elk.spacing.edgeEdge": "8",
      // Fewer crossing-minimization sweeps on big functions: a few hundred
      // milliseconds instead of seconds, for a slightly less tidy picture.
      "elk.layered.thoroughness": big ? "1" : "7",
      "elk.separateConnectedComponents": "false",
    },
    children: nodes.map((n) => ({ id: n.id, width: n.width, height: n.height })),
    edges: edges.map((e): ElkExtendedEdge => ({ id: e.id, sources: [e.from], targets: [e.to] })),
  };
  const out = await engine().layout(graph);
  const placed: Placed = { nodes: new Map(), edges: new Map(), width: out.width ?? 0, height: out.height ?? 0, ms: 0 };
  for (const c of out.children ?? []) placed.nodes.set(c.id, { x: c.x ?? 0, y: c.y ?? 0, w: c.width ?? 0, h: c.height ?? 0 });
  for (const e of (out.edges ?? []) as ElkExtendedEdge[]) {
    const pts: { x: number; y: number }[] = [];
    for (const s of e.sections ?? []) {
      if (!pts.length) pts.push(s.startPoint);
      for (const b of s.bendPoints ?? []) pts.push(b);
      pts.push(s.endPoint);
    }
    placed.edges.set(e.id, pts);
  }
  placed.ms = performance.now() - t0;
  return placed;
}
