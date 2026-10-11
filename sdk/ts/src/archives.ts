// Type archives and categories (api_minor 35, feature "type-archive";
// docs/types.md#type-archives). An archive is a self-contained C header
// plus a JSON sidecar of content hashes, categories, provenance and the
// data model. ExportTypeArchive writes one; importing one is ParseC with
// the sidecar (the hashes are checked, ParseCResponse.archive) and one
// AppendAssertions with import:archive provenance, whose version is the
// archive's origin, so exporting what an archive brought gives the same
// files. Re-importing an archive changes nothing.
//
//   const a = await exportTypeArchive(rk, { programId, scope: TypeArchiveScope.ALL });
//   const parsed = await parseTypeArchive(rk, other, { header: a.header, sidecar: a.sidecar });
//   await importTypeArchive(rk, other, parsed);
import { create, type MessageInitShape } from "@bufbuild/protobuf";

import {
  AppendAssertionsRequestSchema,
  AssertionBodySchema,
  type AppendAssertionsResponse,
  type AssertionBody,
} from "./gen/revkit/v1/assertion_pb";
import { ProvenanceKind, type ReadOptionsSchema } from "./gen/revkit/v1/common_pb";
import type {
  ExportTypeArchiveRequestSchema,
  ExportTypeArchiveResponse,
  ParseCResponse,
} from "./gen/revkit/v1/types_pb";
import { headerImportBodies, type HeaderImportOptions } from "./headers";
import type { Revkit } from "./index";

export const TYPE_ARCHIVE_FEATURE = "type-archive";

/** The program's types as an archive (header, sidecar and their names). */
export function exportTypeArchive(rk: Revkit, request: MessageInitShape<typeof ExportTypeArchiveRequestSchema>): Promise<ExportTypeArchiveResponse> {
  return rk.types.exportTypeArchive(request);
}

export interface TypeArchiveFiles {
  header: string;
  sidecar: string;
  /** The header's file name (default: the sidecar's). */
  headerName?: string;
}

/** The header's name the sidecar records, if it is a sidecar at all. */
export function sidecarHeaderName(sidecar: string): string | undefined {
  try {
    const s = JSON.parse(sidecar) as { header?: unknown };
    return typeof s.header === "string" && s.header ? s.header : undefined;
  } catch {
    return undefined;
  }
}

/** ParseC of an archive's header with its sidecar: for the sidecar's data
 * model, checked against its hashes. The response previews the import
 * like a header's (named types new, replacing or identical) and says how
 * the header compares with the sidecar (`archive`). */
export function parseTypeArchive(rk: Revkit, programId: string, files: TypeArchiveFiles,
                                 read?: MessageInitShape<typeof ReadOptionsSchema>): Promise<ParseCResponse> {
  const name = files.headerName ?? sidecarHeaderName(files.sidecar) ?? "archive.h";
  return rk.types.parseC({
    programId,
    sources: [{ kind: { case: "text", value: files.header }, name }],
    archiveSidecar: files.sidecar,
    ...(read ? { read } : {}),
  });
}

/** What imports a parsed archive: headerImportBodies with an archive's
 * defaults (a name only the library archive defines is imported too, and
 * every name is filed under the archive's category). Empty when the
 * program has the archive already. */
export function typeArchiveImportBodies(parsed: ParseCResponse, options: HeaderImportOptions = {}): AssertionBody[] {
  return headerImportBodies(parsed, { includeLibrary: true, categories: "all", ...options });
}

export interface ImportTypeArchiveOptions extends HeaderImportOptions {
  /** Default: a fresh "archive-..." session, so this import alone can be undone. */
  session?: string;
  reason?: string;
  /** Default import:archive (an admin's against a daemon with accounts),
   * the version the archive's origin; give {} to have the daemon stamp the
   * caller. */
  provenance?: { kind?: ProvenanceKind; id?: string; version?: string };
  /** Import even when types don't parse to the sidecar's hashes. */
  allowMismatches?: boolean;
}

/** Imports a parsed archive in one AppendAssertions (one revision, one
 * undo). Returns null when there is nothing to do: every type is the
 * program's already, filed where the archive files it. */
export async function importTypeArchive(rk: Revkit, programId: string, parsed: ParseCResponse,
                                        options: ImportTypeArchiveOptions = {}): Promise<AppendAssertionsResponse | null> {
  const check = parsed.archive;
  if (!check) throw new Error("not a type archive's parse: parse it with its sidecar (parseTypeArchive)");
  if (check.mismatches.length && !options.allowMismatches) {
    const keys = check.mismatches.slice(0, 5).map((m) => m.key).join(", ");
    throw new Error(`${check.mismatches.length} type(s) don't parse to the sidecar's hashes (${keys}${check.mismatches.length > 5 ? ", ..." : ""})`);
  }
  const assertions = typeArchiveImportBodies(parsed, options).map((body) => ({ body }));
  if (!assertions.length) return null;
  const session = options.session ?? `archive-${Math.random().toString(16).slice(2, 14)}`;
  const who = options.provenance ?? { kind: ProvenanceKind.IMPORT, id: "archive", version: check.origin };
  return rk.assertions.appendAssertions(create(AppendAssertionsRequestSchema, {
    programId,
    assertions,
    provenance: { version: "", ...who, session, reason: options.reason ?? "" },
  }));
}

/** A category path as the daemon stores it ("/net/http"; "" the top), or
 * null for one it refuses. */
export function normalizeCategory(path: string): string | null {
  if (path === "" || path === "/") return "";
  if (!path.startsWith("/") || path.length > 1024) return null;
  const parts = path.slice(1).split("/");
  if (parts.length && parts[parts.length - 1] === "") parts.pop();
  if (parts.length > 32) return null;
  for (const p of parts) if (!p || p === "." || p === ".." || /[\x00-\x1f\x7f]/.test(p)) return null;
  return parts.length ? `/${parts.join("/")}` : "";
}

/** Bodies filing named types ("struct cJSON") under a category ("" or "/":
 * the top). */
export function typeCategoryBodies(keys: string[], path: string): AssertionBody[] {
  return keys.map((namedKey) => create(AssertionBodySchema, { kind: { case: "typeCategory", value: { namedKey, path } } }));
}

/** Files named types under a category, in one request. */
export function setTypeCategory(rk: Revkit, programId: string, keys: string[], path: string,
                                provenance: { kind: ProvenanceKind; id?: string; session?: string; reason?: string }): Promise<AppendAssertionsResponse> {
  return rk.assertions.appendAssertions(create(AppendAssertionsRequestSchema, {
    programId,
    assertions: typeCategoryBodies(keys, path).map((body) => ({ body })),
    provenance,
  }));
}
