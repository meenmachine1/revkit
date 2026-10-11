// Raw layout detection (ProjectService.DetectRawLayout, api_minor 23,
// feature "raw-detect"): for a file with no header that says what it is,
// what a raw import needs (language, load address, header offset, regions),
// each answer with a confidence and its evidence.
//
// DetectRawLayout is one blocking call of a few seconds. detectRawLayout()
// here sends a random detect_id with it and, while it runs, polls
// GetRawDetectProgress into onProgress; aborting its signal stops the
// detection on the daemon (CancelRawDetect: dropping the HTTP request alone
// wouldn't) and rejects with Code.Canceled.
import type { MessageInitShape } from "@bufbuild/protobuf";
import { Code, ConnectError, type Client } from "@connectrpc/connect";

import {
  DetectConfidence, type DetectRawLayoutRequestSchema, type DetectRawLayoutResponse, type GetRawDetectProgressResponse,
  type ProjectService,
} from "./gen/revkit/v1/project_pb";

/** GetServerInfo's feature for DetectRawLayout, GetRawDetectProgress and CancelRawDetect. */
export const RAW_DETECT_FEATURE = "raw-detect";

export interface DetectRawLayoutCallOptions {
  /** Called with the detection's progress about every `pollMs` while it runs. */
  onProgress?: (progress: GetRawDetectProgressResponse) => void;
  /** Aborting it stops the detection; the promise rejects with Code.Canceled. */
  signal?: AbortSignal;
  /** Time between progress polls (default 250 ms), one request at a time. */
  pollMs?: number;
}

/** A random detect_id: 96 bits, hex. */
export function newDetectId(): string {
  const b = new Uint8Array(12);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

/** "high", "medium" or "low"; "" when unset. */
export function confidenceName(c: DetectConfidence): "high" | "medium" | "low" | "" {
  switch (c) {
    case DetectConfidence.HIGH: return "high";
    case DetectConfidence.MEDIUM: return "medium";
    case DetectConfidence.LOW: return "low";
    default: return "";
  }
}

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/**
 * Runs DetectRawLayout, following it with GetRawDetectProgress and stopping
 * it when `signal` aborts. The request's detectId is chosen here unless it
 * has one. Nothing is imported: pass a suggestion's `options` to
 * ImportProgram once the user has agreed to it.
 */
export async function detectRawLayout(
  rk: { projects: Client<typeof ProjectService> },
  request: MessageInitShape<typeof DetectRawLayoutRequestSchema>,
  options: DetectRawLayoutCallOptions = {},
): Promise<DetectRawLayoutResponse> {
  const detectId = request.detectId || newDetectId();
  const projectId = request.projectId ?? "";
  const { signal, onProgress, pollMs = 250 } = options;
  if (signal?.aborted) throw new ConnectError("detection cancelled", Code.Canceled);
  const call = new AbortController();
  let ended = false;

  // The daemon may not have seen the id yet (the request is still on its
  // way): ask again for a moment, then give up (the call is aborted anyway).
  const stopOnDaemon = async () => {
    for (let i = 0; i < 10; i++) {
      try {
        await rk.projects.cancelRawDetect({ projectId, detectId });
        return;
      } catch (e) {
        if (!(e instanceof ConnectError) || e.code !== Code.NotFound) return;
      }
      await sleep(100);
    }
  };
  const onAbort = () => {
    void stopOnDaemon().finally(() => call.abort());
  };
  signal?.addEventListener("abort", onAbort, { once: true });

  let timer: ReturnType<typeof setTimeout> | undefined;
  const tick = async () => {
    timer = undefined;
    if (ended) return;
    try {
      const p = await rk.projects.getRawDetectProgress({ projectId, detectId });
      if (ended) return;
      onProgress?.(p);
      if (p.done) return;
    } catch (e) {
      // Not started yet: ask again. A daemon that can't answer at all: stop.
      if (e instanceof ConnectError && (e.code === Code.Unimplemented || e.code === Code.PermissionDenied)) return;
    }
    if (!ended) timer = setTimeout(() => void tick(), pollMs);
  };
  if (onProgress) timer = setTimeout(() => void tick(), Math.min(50, pollMs));

  try {
    return await rk.projects.detectRawLayout({ ...request, detectId }, { signal: call.signal });
  } catch (e) {
    // Stopped by the caller: say so, whichever way the call ended.
    if (signal?.aborted) throw new ConnectError("detection cancelled", Code.Canceled);
    throw e;
  } finally {
    ended = true;
    if (timer !== undefined) clearTimeout(timer);
    signal?.removeEventListener("abort", onAbort);
  }
}
