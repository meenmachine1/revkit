// Folders and project archives (api_minor 37; docs/api.md, "Folders" and
// "Project archives").
//
// Folders: ListPrograms reports a project's folders (ProjectFolder, with
// its path) and each program's folder (ProgramInfo.folderId, folderPath).
// The RPCs name folders by id; the helpers here take paths ("/libs/json")
// and create what is missing. buildProjectTree() turns a ListPrograms
// response into a tree a project window draws.
//
// Archives: ExportProject streams a .rkproj file; exportProject() collects
// it. Importing one sends the file in pieces (UploadChunk) and then names
// the upload (ImportProjectArchive); importProjectArchive() does both, and
// uploads the binaries an annotations-only archive needs.
import type { MessageInitShape } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";

import { ProvenanceKind, type Provenance, type ProvenanceSchema } from "./gen/revkit/v1/common_pb";
import type {
  ExportProjectRequestSchema, ImportProjectArchiveResponse, ListProgramsResponse, ProgramInfo, ProjectArchiveManifest,
  ProjectFolder,
} from "./gen/revkit/v1/project_pb";
import type { Revkit } from "./index";

/** GetServerInfo's feature for CreateFolder, RenameFolder, DeleteFolder, MoveToFolder and the folder fields. */
export const PROJECT_FOLDERS_FEATURE = "project-folders";
/** GetServerInfo's feature for ExportProject, UploadChunk and ImportProjectArchive. */
export const PROJECT_ARCHIVE_FEATURE = "project-archive";
/** The archive's file name extension. */
export const ARCHIVE_EXTENSION = ".rkproj";

type ProvenanceInit = MessageInitShape<typeof ProvenanceSchema>;

// --- Paths and the tree ------------------------------------------------------

/** "/a//b/" -> "/a/b"; "" and "/" -> "/". Names may not be "." or "..". */
export function normalizeFolderPath(path: string): string {
  const parts = path.split("/").filter((p) => p !== "");
  for (const p of parts) if (p === "." || p === "..") throw new Error(`folder path ${path}: "${p}" is not a folder name`);
  return "/" + parts.join("/");
}

/** The parent of a folder path ("/a/b" -> "/a", "/a" -> "/"). */
export function parentFolderPath(path: string): string {
  const p = normalizeFolderPath(path);
  const at = p.lastIndexOf("/");
  return at <= 0 ? "/" : p.slice(0, at);
}

/** The folder at a path among `folders` (the first by id when two share it); "" for the root; undefined if none. */
export function folderIdAt(folders: readonly ProjectFolder[], path: string): string | undefined {
  const p = normalizeFolderPath(path);
  if (p === "/") return "";
  const hits = folders.filter((f) => f.path === p).sort((a, b) => (a.folderId < b.folderId ? -1 : a.folderId > b.folderId ? 1 : 0));
  return hits[0]?.folderId;
}

/** One folder of a project's tree, with what is in it. The root has folderId "" and path "/". */
export interface FolderNode {
  folderId: string;
  name: string;
  path: string;
  folder?: ProjectFolder;
  folders: FolderNode[];
  programs: ProgramInfo[];
}

/**
 * The tree of a ListPrograms (or OpenProject) response: folders by name,
 * programs by name, a program whose folder is unknown at the root.
 */
export function buildProjectTree(listing: Pick<ListProgramsResponse, "folders" | "programs">): FolderNode {
  const root: FolderNode = { folderId: "", name: "", path: "/", folders: [], programs: [] };
  const nodes = new Map<string, FolderNode>([["", root]]);
  for (const f of listing.folders) nodes.set(f.folderId, { folderId: f.folderId, name: f.name, path: f.path, folder: f, folders: [], programs: [] });
  for (const f of listing.folders) (nodes.get(f.parentId) ?? root).folders.push(nodes.get(f.folderId)!);
  for (const p of listing.programs) (nodes.get(p.folderId) ?? root).programs.push(p);
  const byName = (a: { name: string }, b: { name: string }) => a.name.localeCompare(b.name);
  for (const n of nodes.values()) {
    n.folders.sort(byName);
    n.programs.sort(byName);
  }
  return root;
}

/** Every folder of a tree, parents first (the root included when `withRoot`). */
export function walkFolders(root: FolderNode, withRoot = false): FolderNode[] {
  const out: FolderNode[] = [];
  const visit = (n: FolderNode) => {
    out.push(n);
    n.folders.forEach(visit);
  };
  if (withRoot) visit(root);
  else root.folders.forEach(visit);
  return out;
}

/** Whether `folderId` is `ancestorId` or below it, in a tree. */
export function folderWithin(root: FolderNode, folderId: string, ancestorId: string): boolean {
  if (ancestorId === "") return true;
  const anc = walkFolders(root).find((n) => n.folderId === ancestorId);
  return !!anc && walkFolders(anc, true).some((n) => n.folderId === folderId);
}

// --- Folders through the daemon ------------------------------------------------

async function listing(rk: Revkit, projectId: string) {
  return rk.projects.listPrograms({ projectId });
}

/** The folder id at a path ("" for the root); NotFound if there is none. */
export async function resolveFolder(rk: Revkit, projectId: string, path: string): Promise<string> {
  const id = folderIdAt((await listing(rk, projectId)).folders, path);
  if (id === undefined) throw new ConnectError(`no folder ${normalizeFolderPath(path)} in project ${projectId}`, Code.NotFound);
  return id;
}

/**
 * The folder at a path, creating it and any missing parents (one
 * CreateFolder each). Returns its id ("" for the root).
 */
export async function ensureFolder(rk: Revkit, projectId: string, path: string, provenance?: ProvenanceInit): Promise<string> {
  const p = normalizeFolderPath(path);
  if (p === "/") return "";
  const folders = [...(await listing(rk, projectId)).folders];
  let parent = "";
  let at = "";
  for (const name of p.slice(1).split("/")) {
    at += "/" + name;
    let id = folderIdAt(folders, at);
    if (id === undefined) {
      const r = await rk.projects.createFolder({ projectId, parentId: parent, name, provenance: provenance ?? defaultProvenance() });
      if (!r.folder) throw new ConnectError(`creating ${at} returned no folder`, Code.Internal);
      folders.push(r.folder);
      id = r.folder.folderId;
    }
    parent = id;
  }
  return parent;
}

/** Moves programs and folders (by id) into the folder at `path`, creating it if needed. One revision. */
export async function moveToFolderPath(
  rk: Revkit, projectId: string, path: string, items: { programIds?: string[]; folderIds?: string[] }, provenance?: ProvenanceInit,
) {
  const folderId = await ensureFolder(rk, projectId, path, provenance);
  return rk.projects.moveToFolder({
    projectId, folderId, programIds: items.programIds ?? [], folderIds: items.folderIds ?? [], provenance: provenance ?? defaultProvenance(),
  });
}

/** Undoes folder edits (their assertions' seqs): one RetractAssertions by project. */
export async function undoFolderEdit(rk: Revkit, projectId: string, seqs: bigint[], provenance?: ProvenanceInit) {
  return rk.assertions.retractAssertions({ projectId, seqs, provenance: provenance ?? defaultProvenance() });
}

function defaultProvenance(): ProvenanceInit {
  // USER with no id: an authenticating daemon fills in the caller.
  return { kind: ProvenanceKind.USER };
}

// --- Archives ----------------------------------------------------------------

export interface ExportedArchive {
  /** "<project>.rkproj", as the daemon suggests it. */
  fileName: string;
  manifest?: ProjectArchiveManifest;
  data: Uint8Array;
}

/** ExportProject, collected: the summary and the archive's bytes. onBytes sees the running total. */
export async function exportProject(
  rk: Revkit, req: MessageInitShape<typeof ExportProjectRequestSchema>,
  opts: { signal?: AbortSignal; onBytes?: (received: number) => void } = {},
): Promise<ExportedArchive> {
  let fileName = "";
  let manifest: ProjectArchiveManifest | undefined;
  const parts: Uint8Array[] = [];
  let total = 0;
  for await (const msg of rk.projects.exportProject(req, { signal: opts.signal })) {
    if (msg.summary) {
      fileName = msg.summary.fileName;
      manifest = msg.summary.manifest;
    }
    if (msg.data.length) {
      parts.push(msg.data);
      total += msg.data.length;
      opts.onBytes?.(total);
    }
  }
  const data = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    data.set(p, at);
    at += p.length;
  }
  return { fileName: fileName || "project" + ARCHIVE_EXTENSION, manifest, data };
}

/** Bytes or a Blob (a browser File). */
export type FileData = Uint8Array | Blob;

const sizeOf = (d: FileData) => (d instanceof Uint8Array ? d.length : d.size);
async function slice(d: FileData, from: number, to: number): Promise<Uint8Array> {
  return d instanceof Uint8Array ? d.subarray(from, to) : new Uint8Array(await d.slice(from, to).arrayBuffer());
}

/** Default piece size for uploads: 4 MiB, well under the daemon's message limit. */
export const UPLOAD_CHUNK_BYTES = 4 << 20;

/** Sends a file in pieces (UploadChunk); resolves to its upload_id. */
export async function uploadFile(
  rk: Revkit, data: FileData,
  opts: { fileName?: string; chunkBytes?: number; signal?: AbortSignal; onProgress?: (sent: number, total: number) => void } = {},
): Promise<string> {
  const total = sizeOf(data);
  if (total === 0) throw new ConnectError("the file is empty", Code.InvalidArgument);
  const step = opts.chunkBytes ?? UPLOAD_CHUNK_BYTES;
  let id = "";
  for (let at = 0; at < total; at += step) {
    const piece = await slice(data, at, Math.min(total, at + step));
    const r = await rk.projects.uploadChunk(
      { uploadId: id, offset: BigInt(at), data: piece, totalSize: id ? 0n : BigInt(total), fileName: id ? "" : opts.fileName ?? "" },
      { signal: opts.signal },
    );
    id = r.uploadId;
    opts.onProgress?.(Number(r.received), total);
  }
  return id;
}

export interface ImportArchiveOptions {
  /** Into this existing project (as new programs); else a new project. */
  projectId?: string;
  /** The new project's name (default: the archive's). */
  newProjectName?: string;
  /** Where the archive's tree goes in projectId (default: the root). */
  folderId?: string;
  /** Binaries an annotations-only archive needs (matched by sha256; others are ignored). */
  binaries?: FileData[];
  /** A directory on the daemon's host to search for them (admin). */
  searchDir?: string;
  skipMissing?: boolean;
  /** Only describe the archive and which binaries were found. */
  inspectOnly?: boolean;
  /** An upload_id of the archive already sent (skip sending it again). */
  uploadId?: string;
  provenance?: ProvenanceInit;
  signal?: AbortSignal;
  onUpload?: (what: string, sent: number, total: number) => void;
}

/** The archive and its binaries uploaded, then ImportProjectArchive; returns the response and the archive's upload_id. */
export async function importProjectArchive(
  rk: Revkit, archive: FileData | null, opts: ImportArchiveOptions = {},
): Promise<{ response: ImportProjectArchiveResponse; uploadId: string }> {
  let uploadId = opts.uploadId ?? "";
  if (!uploadId) {
    if (!archive) throw new ConnectError("no archive to import", Code.InvalidArgument);
    uploadId = await uploadFile(rk, archive, {
      fileName: archive instanceof Blob && "name" in archive ? String((archive as File).name) : "archive" + ARCHIVE_EXTENSION,
      signal: opts.signal, onProgress: (s, t) => opts.onUpload?.("archive", s, t),
    });
  }
  const binaries = [];
  for (const [i, b] of (opts.binaries ?? []).entries()) {
    const id = await uploadFile(rk, b, { signal: opts.signal, onProgress: (s, t) => opts.onUpload?.(`binary ${i + 1}`, s, t) });
    binaries.push({ source: { case: "uploadId" as const, value: id } });
  }
  const response = await rk.projects.importProjectArchive({
    archive: { source: { case: "uploadId", value: uploadId } },
    projectId: opts.projectId ?? "",
    newProjectName: opts.newProjectName ?? "",
    folderId: opts.folderId ?? "",
    binaries,
    searchDir: opts.searchDir ?? "",
    skipMissing: opts.skipMissing ?? false,
    inspectOnly: opts.inspectOnly ?? false,
    provenance: opts.provenance ?? defaultProvenance(),
  }, { signal: opts.signal });
  return { response, uploadId };
}

/** The lowercase hex SHA-256 of a file (WebCrypto), to match binaries to an archive's programs. */
export async function sha256Hex(data: FileData): Promise<string> {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(await data.arrayBuffer());
  const digest = await crypto.subtle.digest("SHA-256", bytes as Uint8Array<ArrayBuffer>);
  return Array.from(new Uint8Array(digest), (x) => x.toString(16).padStart(2, "0")).join("");
}

export type { Provenance };

// Rebase (api_minor 42; docs/memory-map.md, "Rebase: setting the image
// base"): ProjectService.SetImageBase moves a program and everything recorded
// about it to a new image base, as one undoable edit.
//
//   const r = await rk.projects.setImageBase({ programId, imageBase: 0x8000000n, provenance: { reason: "the real base" } });
//   await rk.assertions.retractAssertions({ programId, seqs: [r.assertion!.seq] });  // and back
export const REBASE_FEATURE = "rebase";
