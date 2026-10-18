// Trace value across calls (api_minor 89, feature "value-trace"; docs/ui.md
// "Tracing a value across calls"): QueryService.TraceValue from the
// decompiler's token, backward (where the value comes from) or forward
// (where it goes), through direct calls. The dialog lists each function
// the trace reached with the C lines it touches (a click goes there), the
// calls it crossed, and where it stopped without knowing more (indirect
// calls, imports, memory, functions nothing calls, budgets).

import { TraceDirection, TraceEdgeKind, TraceUnknownKind, type Revkit, type TraceValueResponse } from "@revkit/api";

type Position = { line: number; token: number };
import { errText } from "../data/format";
import { h, overlayRoot } from "./dom";

export const TRACE_FEATURE = "value-trace";

const UNKNOWN: Record<number, string> = {
  [TraceUnknownKind.INDIRECT_CALL]: "indirect call",
  [TraceUnknownKind.EXTERNAL_CALL]: "outside the program",
  [TraceUnknownKind.MEMORY]: "through memory",
  [TraceUnknownKind.NO_CALLERS]: "no callers",
  [TraceUnknownKind.DECOMPILE_FAILED]: "decompiler failed",
  [TraceUnknownKind.BUDGET]: "limit reached",
  [TraceUnknownKind.UNMATCHED]: "doesn't pair",
};

const hex = (v: bigint) => "0x" + v.toString(16);

export interface TraceOptions {
  programId: string;
  entry: bigint;
  token: Position;
  backward: boolean;
  /** Goes to an address (a function's line, a call). */
  navigate: (address: bigint) => void;
  /** The start function's traced tokens, to highlight in the decompiler. */
  highlight?: (tokens: Position[], label: string) => void;
}

/** One line per crossing: "main → combine (argument, at 0x401234)". */
function crossings(r: TraceValueResponse): { text: string; address: bigint }[] {
  const out: { text: string; address: bigint }[] = [];
  const seen = new Set<string>();
  for (const e of r.edges) {
    if (e.kind === TraceEdgeKind.DATAFLOW) continue;
    const from = r.nodes[e.from], to = r.nodes[e.to];
    if (!from || !to) continue;
    const fa = r.functions[from.function]?.name ?? "?", fb = r.functions[to.function]?.name ?? "?";
    const what = e.kind === TraceEdgeKind.ARGUMENT ? `${from.text || "argument"} → ${to.text || "parameter"}` : `${from.text || "returned value"} → ${to.text || "call's value"}`;
    const text = `${fa} → ${fb}: ${what} (${e.kind === TraceEdgeKind.ARGUMENT ? "argument" : "return"})`;
    if (seen.has(text)) continue;
    seen.add(text);
    out.push({ text, address: e.address?.offset ?? 0n });
  }
  return out;
}

export async function showTraceDialog(rk: Revkit, o: TraceOptions) {
  const restore = document.activeElement as HTMLElement | null;
  const direction = o.backward ? "where it comes from" : "where it goes";
  const body = h("div", { class: "bi-body tr-body", "data-testid": "trace-body" }, h("div", { class: "dim" }, "Tracing…"));
  const title = h("div", { class: "modal-title" }, `Trace across calls: ${direction}`);
  const close = () => {
    backdrop.remove();
    restore?.focus({ preventScroll: true });
  };
  const box = h(
    "div",
    { class: "modal bi tr", role: "dialog", tabindex: "-1", "aria-label": "Trace value across calls", "data-testid": "trace-dialog" },
    h("div", { class: "libs-head" }, title, h("span", { class: "spacer" }), h("button", { class: "btn", type: "button", "data-testid": "trace-close", onclick: close, text: "Close" })),
    body,
    h("div", { class: "modal-hint" }, "Through direct calls, matched call by call · click a line to go there · Esc closes"),
  );
  const backdrop = h("div", { class: "backdrop" }, box);
  box.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      e.stopPropagation();
      close();
    }
  });
  backdrop.addEventListener("mousedown", (e) => {
    if (e.target === backdrop) close();
  });
  overlayRoot().append(backdrop);
  box.focus();

  let r: TraceValueResponse;
  try {
    r = await rk.queries.traceValue({
      programId: o.programId,
      function: { offset: o.entry },
      direction: o.backward ? TraceDirection.BACKWARD : TraceDirection.FORWARD,
      from: { case: "token", value: o.token },
    });
  } catch (e) {
    body.replaceChildren(h("div", { class: "bi-warn", "data-testid": "trace-error" }, errText(e)));
    return;
  }
  title.textContent = `Trace across calls: ${direction} — ${r.start}`;
  const parts: HTMLElement[] = [];
  parts.push(
    h(
      "div",
      { class: "dim", "data-testid": "trace-summary" },
      `${r.functions.length} function${r.functions.length === 1 ? "" : "s"}, ${r.nodes.length} value${r.nodes.length === 1 ? "" : "s"}` +
        (r.unknowns.length ? `, ${r.unknowns.length} place${r.unknowns.length === 1 ? "" : "s"} it couldn't follow` : "") +
        (r.truncated ? " (a limit stopped it)" : ""),
    ),
  );
  const cross = crossings(r);
  if (cross.length)
    parts.push(
      h(
        "details",
        { class: "bi-details", open: true },
        h("summary", {}, `Calls crossed (${cross.length})`),
        h(
          "div",
          { class: "bi-table", "data-testid": "trace-crossings" },
          ...cross.map((c) => h("button", { class: "tr-row link mono", type: "button", "data-testid": "trace-crossing", title: `Go to ${hex(c.address)}`, onclick: () => { close(); o.navigate(c.address); } }, c.text)),
        ),
      ),
    );
  r.functions.forEach((f, i) => {
    const depth = f.depth === 0 ? "start" : f.depth > 0 ? `callee, ${f.depth} down` : `caller, ${-f.depth} up`;
    const lines = f.lines.map((l) =>
      h(
        "button",
        {
          class: "tr-row link mono",
          type: "button",
          "data-testid": "trace-line",
          "data-function": f.name,
          title: `Go to ${f.name}`,
          onclick: () => {
            close();
            o.navigate(f.addresses[0]?.offset ?? f.entry?.offset ?? 0n);
          },
        },
        h("span", { class: "tr-ln dim" }, String(l.line + 1)),
        h("span", {}, l.text.trim()),
      ),
    );
    parts.push(
      h(
        "details",
        { class: "bi-details", open: i < 6, "data-testid": "trace-function", "data-name": f.name },
        h("summary", {}, h("span", { class: "mono" }, f.name), h("span", { class: "dim" }, ` · ${depth} · ${f.lines.length} line${f.lines.length === 1 ? "" : "s"}`)),
        lines.length ? h("div", { class: "bi-table" }, ...lines) : h("div", { class: "dim" }, "No line prints the traced values (they pass through registers or temporaries)."),
      ),
    );
  });
  if (r.unknowns.length)
    parts.push(
      h(
        "details",
        { class: "bi-details", open: true },
        h("summary", {}, `Couldn't follow (${r.unknowns.length})`),
        h(
          "div",
          { class: "bi-table", "data-testid": "trace-unknowns" },
          ...r.unknowns.map((u) => {
            const node = u.node !== undefined ? r.nodes[u.node] : undefined;
            const where = node ? `${r.functions[node.function]?.name ?? "?"}${node.text ? ` · ${node.text}` : ""}` : "";
            return h(
              "div",
              { class: "bi-row bi-kv", "data-testid": "trace-unknown", "data-kind": UNKNOWN[u.kind] ?? "" },
              h("span", { class: "dim" }, UNKNOWN[u.kind] ?? "?"),
              h("span", {}, [u.detail, where].filter(Boolean).join(" — ") + (u.address ? ` (${hex(u.address.offset)})` : "")),
            );
          }),
        ),
      ),
    );
  body.replaceChildren(...parts);
  if (o.highlight) {
    // The start function's traced tokens, highlighted where the trace began.
    const start = r.functions[0];
    if (start) o.highlight(start.lines.flatMap((l) => l.tokens.map((t) => ({ line: l.line, token: t }))), `Trace (${direction}) of ${r.start}`);
  }
}
