// revkit API client for TypeScript (browser, Tauri, Node).
//
// The generated descriptors in ./gen are the contract; Connect-ES builds a
// typed client from each service. In a browser use connectTransport() (or
// grpcWebTransport()) against rk-daemon's HTTP port; the same bundle works in
// Tauri and in a plain tab because the daemon serves the browser protocols
// itself.
//
// Against a daemon with authentication (docs/security.md): a page served by
// rk-daemon logs in with AuthService.Login({sessionCookie: true}) and sends
// the CSRF token it gets back with every call (csrf option); anything else
// (Node, Tauri, another origin) sends a token (token option). For Node over
// TLS with a pinned self-signed certificate, see ../node/index.ts.
import { createClient, type Client, type Interceptor, type Transport } from "@connectrpc/connect";
import { createConnectTransport, createGrpcWebTransport } from "@connectrpc/connect-web";

import { AnalysisService } from "./gen/revkit/v1/analysis_pb";
import { AssertionService } from "./gen/revkit/v1/assertion_pb";
import { AuthService } from "./gen/revkit/v1/auth_pb";
import { BSimService } from "./gen/revkit/v1/bsim_pb";
import { DebugService } from "./gen/revkit/v1/debugger_pb";
import { DiffService } from "./gen/revkit/v1/diff_pb";
import { EmulatorService } from "./gen/revkit/v1/emulator_pb";
import { FileSystemService } from "./gen/revkit/v1/filesystem_pb";
import { MetaService } from "./gen/revkit/v1/meta_pb";
import { PatchService } from "./gen/revkit/v1/patch_pb";
import { PluginService } from "./gen/revkit/v1/plugin_pb";
import { PresenceService } from "./gen/revkit/v1/presence_pb";
import { ProjectService } from "./gen/revkit/v1/project_pb";
import { QueryService } from "./gen/revkit/v1/query_pb";
import { ScriptService } from "./gen/revkit/v1/script_pb";
import { SubscriptionService } from "./gen/revkit/v1/subscription_pb";
import { TypeService } from "./gen/revkit/v1/types_pb";

export * from "./gen/revkit/v1/analysis_pb";
export * from "./gen/revkit/v1/assertion_pb";
export * from "./gen/revkit/v1/auth_pb";
export * from "./gen/revkit/v1/bsim_pb";
export * from "./gen/revkit/v1/common_pb";
export * from "./gen/revkit/v1/debugger_pb";
export * from "./gen/revkit/v1/decompile_pb";
export * from "./gen/revkit/v1/diff_pb";
export * from "./gen/revkit/v1/emulator_pb";
export * from "./gen/revkit/v1/filesystem_pb";
export * from "./gen/revkit/v1/listing_pb";
export * from "./gen/revkit/v1/meta_pb";
export * from "./gen/revkit/v1/patch_pb";
export * from "./gen/revkit/v1/plugin_pb";
export * from "./gen/revkit/v1/presence_pb";
export * from "./gen/revkit/v1/project_pb";
export * from "./gen/revkit/v1/query_pb";
export * from "./gen/revkit/v1/script_pb";
export * from "./gen/revkit/v1/subscription_pb";
export * from "./gen/revkit/v1/types_pb";
export * from "./detect";

export interface Revkit {
  meta: Client<typeof MetaService>;
  projects: Client<typeof ProjectService>;
  assertions: Client<typeof AssertionService>;
  queries: Client<typeof QueryService>;
  subscriptions: Client<typeof SubscriptionService>;
  analysis: Client<typeof AnalysisService>;
  /** WebAssembly plugins (api_minor 6, feature "plugins"). */
  plugins: Client<typeof PluginService>;
  /** Collaborators' cursors (feature "presence", api_minor 5). */
  presence: Client<typeof PresenceService>;
  /** Login, identity, accounts and API tokens (feature "auth", api_minor 13). */
  auth: Client<typeof AuthService>;
  /** Emulation sessions (api_minor 12, feature "emulator"). */
  emulator: Client<typeof EmulatorService>;
  /** Debug sessions: the emulator, GDB remote stubs, launched processes,
   * saved traces (api_minor 14, features "debugger", "debugger-live"). */
  debugger: Client<typeof DebugService>;
  /** Binary diffing and version tracking: sessions, matches, markup
   * porting (api_minor 16, feature "diff"). */
  diff: Client<typeof DiffService>;
  /** Parsing C into types (api_minor 25, feature "parse-c"); see parseC and
   * importHeader. */
  types: Client<typeof TypeService>;
  /** Assembling, patching, export with checksum fixups (api_minor 27,
   * feature "patch"). */
  patch: Client<typeof PatchService>;
  /** Scripts the daemon runs: libraries, runs streaming output, progress
   * and prompts, saving (api_minor 31, feature "scripts-host"); see
   * runScript and scriptsForContext. */
  scripts: Client<typeof ScriptService>;
  /** Container file systems: browse, read, import and extract (api_minor
   * 40, feature "filesystems"); see openFileSystem. */
  filesystems: Client<typeof FileSystemService>;
  /** BSim signature databases: create, attach, ingest, list (api_minor 69,
   * feature "bsim"). */
  bsim: Client<typeof BSimService>;
}

/** One typed client per service, sharing a transport. */
export function createRevkit(transport: Transport): Revkit {
  return {
    meta: createClient(MetaService, transport),
    projects: createClient(ProjectService, transport),
    assertions: createClient(AssertionService, transport),
    queries: createClient(QueryService, transport),
    subscriptions: createClient(SubscriptionService, transport),
    analysis: createClient(AnalysisService, transport),
    plugins: createClient(PluginService, transport),
    presence: createClient(PresenceService, transport),
    auth: createClient(AuthService, transport),
    emulator: createClient(EmulatorService, transport),
    debugger: createClient(DebugService, transport),
    diff: createClient(DiffService, transport),
    types: createClient(TypeService, transport),
    patch: createClient(PatchService, transport),
    scripts: createClient(ScriptService, transport),
    filesystems: createClient(FileSystemService, transport),
    bsim: createClient(BSimService, transport),
  };
}

export * from "./archives";
export * from "./projecttypes";
export * from "./headers";
export * from "./equates";
export * from "./listing";
export * from "./structures";
export * from "./scripting";
export * from "./search";
export * from "./scripts";
export * from "./projects";
export * from "./names";
export * from "./preview";
export * from "./filesystems";

/** How a transport authenticates. Getters are read on every call, so a page
 * can log in or out without building a new transport. */
export interface Credentials {
  /** A session or API token, sent as `authorization: Bearer <token>`. */
  token?: string | (() => string | undefined);
  /** The session's CSRF token, sent as `x-csrf-token` alongside the
   * daemon's session cookie (LoginResponse/WhoAmIResponse.csrfToken). */
  csrf?: string | (() => string | undefined);
}

/** An interceptor adding the credentials' headers to every call. */
export function credentialsInterceptor(c: Credentials): Interceptor {
  const read = (v: string | (() => string | undefined) | undefined) => (typeof v === "function" ? v() : v);
  return (next) => async (req) => {
    const token = read(c.token);
    if (token) req.header.set("authorization", `Bearer ${token}`);
    const csrf = read(c.csrf);
    if (csrf) req.header.set("x-csrf-token", csrf);
    return next(req);
  };
}

/** Connect protocol (JSON by default; binary with useBinaryFormat). */
export function connectTransport(baseUrl = window.location.origin, useBinaryFormat = false, credentials: Credentials = {}): Transport {
  return createConnectTransport({ baseUrl, useBinaryFormat, interceptors: [credentialsInterceptor(credentials)] });
}

/** gRPC-web (binary). */
export function grpcWebTransport(baseUrl = window.location.origin, credentials: Credentials = {}): Transport {
  return createGrpcWebTransport({ baseUrl, interceptors: [credentialsInterceptor(credentials)] });
}
