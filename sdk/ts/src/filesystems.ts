// Container file systems (api_minor 48, feature "filesystems";
// docs/filesystems.md): open an archive, a compressed file, a file system
// image or a firmware package as a tree of files, nested to any depth,
// and read, describe, import and extract its files.
//
// Paths name a file through every layer: '!' separates the layers and each
// layer is "/a/b" with percent-encoded names ("/rootfs.sqfs!/bin/busybox").
// The helpers here take the paths a listing returns and never build one
// from a display name, except joinPath (which encodes).
import type { MessageInitShape } from "@bufbuild/protobuf";

import type { ProvenanceSchema } from "./gen/revkit/v1/common_pb";
import {
  FileSystemEntryKind, type ExtractFromFileSystemResponse, type FileSystemEntry, type FileSystemLayer,
  type FileSystemLimitsSchema, type GetFileSystemFileInfoResponse, type ImportFromFileSystemResponse,
  type ListFileSystemResponse, type OpenFileSystemResponse,
} from "./gen/revkit/v1/filesystem_pb";
import type { ImportOptionsSchema } from "./gen/revkit/v1/project_pb";
import type { Revkit } from "./index";
import { type FileData, uploadFile } from "./projects";

/** GetServerInfo's feature for FileSystemService and ProgramInfo.containerPath. */
export const FILESYSTEMS_FEATURE = "filesystems";

type ProvenanceInit = MessageInitShape<typeof ProvenanceSchema>;
type ImportOptionsInit = MessageInitShape<typeof ImportOptionsSchema>;

// --- Paths -----------------------------------------------------------------------

/** One name as a path component: '%', '!', '/' and control characters escaped. */
export function encodeName(name: string): string {
  let out = "";
  for (const ch of name) {
    const c = ch.codePointAt(0)!;
    if (c < 0x20 || c === 0x7f || ch === "%" || ch === "!" || ch === "/") out += "%" + c.toString(16).toUpperCase().padStart(2, "0");
    else out += ch;
  }
  return out;
}

/** A path for people: escapes decoded ("%21" -> "!"), layers kept. Bytes that aren't UTF-8 show as U+FFFD. */
export function displayPath(path: string): string {
  return path.split("!").map((layer) => {
    const bytes: number[] = [];
    for (let i = 0; i < layer.length; i++) {
      if (layer[i] === "%" && /^[0-9a-fA-F]{2}$/.test(layer.slice(i + 1, i + 3))) {
        bytes.push(parseInt(layer.slice(i + 1, i + 3), 16));
        i += 2;
      } else {
        bytes.push(...new TextEncoder().encode(layer[i]));
      }
    }
    return new TextDecoder().decode(new Uint8Array(bytes)) || "/";
  }).join("!");
}

/** The layers of a path: "/a.zip!/b" -> ["/a.zip", "/b"]. */
export function pathLayers(path: string): string[] {
  return path.split("!").map((l) => l || "/");
}

/** A child's path: joinPath("/a.zip!/", "x/y") -> "/a.zip!/x%2Fy". */
export function joinPath(dir: string, name: string): string {
  return (dir.endsWith("/") ? dir : dir + "/") + encodeName(name);
}

/** The directory above, inside its layer; at a nested container's root, the
 * container file itself ("/a.zip!/" -> "/a.zip"); the outermost root: "/". */
export function parentPath(path: string): string {
  const layers = path.split("!");
  const last = layers[layers.length - 1].replace(/\/+$/, "");
  if (last === "") {
    if (layers.length === 1) return "/";
    return layers.slice(0, -1).join("!");
  }
  const at = last.lastIndexOf("/");
  const up = at <= 0 ? "/" : last.slice(0, at);
  return [...layers.slice(0, -1), up].join("!");
}

/** "file", "directory", "symlink", ... */
export function entryKindName(kind: FileSystemEntryKind): string {
  return FileSystemEntryKind[kind]?.toLowerCase().replace(/_/g, "-") ?? "other";
}

/** True for entries a listing can descend into: directories, and files holding a container. */
export function isBrowsable(e: FileSystemEntry): boolean {
  return e.kind === FileSystemEntryKind.DIRECTORY || e.containerFormat !== "";
}

/** True for files an import would take as a program by default (ELF, PE, a raw image whose header names its language). */
export function isProgram(e: FileSystemEntry): boolean {
  return e.detectedKind === "elf" || e.detectedKind === "pe" || (e.detectedKind === "raw" && e.languageId !== "");
}

// --- Sessions ------------------------------------------------------------------------

export type FileSystemSource =
  | { hostPath: string }
  | { programId: string }
  | { file: FileData; name?: string };

export interface ImportFromFileSystemOptions {
  projectId?: string;
  folderId?: string;
  recursive?: boolean;
  descend?: boolean;
  programsOnly?: boolean;
  detectRaw?: boolean;
  preview?: boolean;
  maxPrograms?: number;
  keepFolders?: boolean;
  options?: ImportOptionsInit;
  provenance?: ProvenanceInit;
  signal?: AbortSignal;
}

/** Bytes sent inline up to this size; larger files are uploaded in pieces. */
export const INLINE_FILE_BYTES = 16 << 20;

/** An open container (FileSystemService session). Close it when done. */
export class FileSystemSession {
  constructor(readonly rk: Revkit, readonly projectId: string, readonly opened: OpenFileSystemResponse) {}

  get id(): string { return this.opened.sessionId; }
  get name(): string { return this.opened.name; }
  get root(): FileSystemLayer | undefined { return this.opened.root; }

  list(path = "/", opts: { detect?: boolean; recursive?: boolean; offset?: number; limit?: number; signal?: AbortSignal } = {}): Promise<ListFileSystemResponse> {
    return this.rk.filesystems.listFileSystem(
      { sessionId: this.id, path, detect: opts.detect ?? true, recursive: opts.recursive ?? false, offset: opts.offset ?? 0, limit: opts.limit ?? 0 },
      { signal: opts.signal });
  }

  /** Every entry of a listing, across pages. */
  async entries(path = "/", opts: { detect?: boolean; recursive?: boolean; signal?: AbortSignal } = {}): Promise<FileSystemEntry[]> {
    const out: FileSystemEntry[] = [];
    for (;;) {
      const page = await this.list(path, { ...opts, offset: out.length, limit: 5000 });
      out.push(...page.entries);
      if (page.entries.length === 0 || out.length >= page.total) return out;
    }
  }

  /** A file's bytes (all of them by default), in 4 MiB pieces. */
  async read(path: string, offset = 0, length?: number, signal?: AbortSignal): Promise<Uint8Array> {
    const parts: Uint8Array[] = [];
    let got = 0;
    for (;;) {
      const want = length === undefined ? 4 << 20 : Math.min(4 << 20, length - got);
      if (want <= 0) break;
      const r = await this.rk.filesystems.readFileSystemFile({ sessionId: this.id, path, offset: BigInt(offset + got), length: BigInt(want) }, { signal });
      parts.push(r.data);
      got += r.data.length;
      if (r.eof || r.data.length === 0) break;
    }
    const out = new Uint8Array(got);
    let at = 0;
    for (const p of parts) { out.set(p, at); at += p.length; }
    return out;
  }

  info(path: string, hashes = false, signal?: AbortSignal): Promise<GetFileSystemFileInfoResponse> {
    return this.rk.filesystems.getFileSystemFileInfo({ sessionId: this.id, path, hashes }, { signal });
  }

  /** Imports files as programs (editor): one named alone whatever it is;
   * directories and containers inside (descend) give their programs only. */
  import(paths: string[], o: ImportFromFileSystemOptions = {}): Promise<ImportFromFileSystemResponse> {
    return this.rk.filesystems.importFromFileSystem({
      sessionId: this.id, projectId: o.projectId ?? this.projectId, folderId: o.folderId ?? "", paths,
      recursive: o.recursive ?? false, descend: o.descend ?? false, programsOnly: o.programsOnly ?? false,
      detectRaw: o.detectRaw ?? false, preview: o.preview ?? false, maxPrograms: o.maxPrograms ?? 0,
      keepFolders: o.keepFolders ?? false, options: o.options ?? { analyze: true }, provenance: o.provenance ?? {},
    }, { signal: o.signal });
  }

  /** Writes files to a directory under --browse-root on the daemon's host (admin). */
  extract(paths: string[], hostDir: string, overwrite = false, signal?: AbortSignal): Promise<ExtractFromFileSystemResponse> {
    return this.rk.filesystems.extractFromFileSystem({ sessionId: this.id, paths, hostDir, overwrite }, { signal });
  }

  async close(): Promise<void> {
    try {
      await this.rk.filesystems.closeFileSystem({ sessionId: this.id });
    } catch {
      // Closed already, or idle too long.
    }
  }
}

/** Opens a container: a host file or directory (admin), a program's stored file, or bytes (admin; uploaded past 16 MiB). */
export async function openFileSystem(rk: Revkit, projectId: string, source: FileSystemSource,
  opts: { limits?: MessageInitShape<typeof FileSystemLimitsSchema>; signal?: AbortSignal; onUpload?: (sent: number, total: number) => void } = {},
): Promise<FileSystemSession> {
  let src: { case: "hostPath"; value: string } | { case: "programId"; value: string } | { case: "uploadId"; value: string } | { case: "content"; value: Uint8Array };
  let name = "";
  if ("hostPath" in source) {
    src = { case: "hostPath", value: source.hostPath };
  } else if ("programId" in source) {
    src = { case: "programId", value: source.programId };
  } else {
    name = source.name ?? (typeof Blob !== "undefined" && source.file instanceof Blob && "name" in source.file ? String((source.file as File).name) : "upload");
    const size = source.file instanceof Uint8Array ? source.file.length : source.file.size;
    if (size <= INLINE_FILE_BYTES) {
      const bytes = source.file instanceof Uint8Array ? source.file : new Uint8Array(await source.file.arrayBuffer());
      src = { case: "content", value: bytes };
    } else {
      src = { case: "uploadId", value: await uploadFile(rk, source.file, { fileName: name, signal: opts.signal, onProgress: opts.onUpload }) };
    }
  }
  const opened = await rk.filesystems.openFileSystem({ projectId, source: src, name, limits: opts.limits ?? {} }, { signal: opts.signal });
  return new FileSystemSession(rk, projectId, opened);
}

/** Container magics a client can check before offering "Open as file system"
 * (the daemon decides; this only avoids offering it for plain ELF/PE). */
export function looksLikeContainer(head: Uint8Array): string {
  const at = (off: number, ...bytes: number[]) => bytes.every((b, i) => head[off + i] === b);
  const ascii = (off: number, s: string) => [...s].every((ch, i) => head[off + i] === ch.charCodeAt(0));
  if (at(0, 0x50, 0x4b, 0x03, 0x04) || at(0, 0x50, 0x4b, 0x05, 0x06)) return "zip";
  if (at(0, 0x1f, 0x8b)) return "gzip";
  if (ascii(0, "BZh")) return "bzip2";
  if (at(0, 0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00)) return "xz";
  if (at(0, 0x28, 0xb5, 0x2f, 0xfd)) return "zstd";
  if (at(0, 0x04, 0x22, 0x4d, 0x18) || at(0, 0x02, 0x21, 0x4c, 0x18)) return "lz4";
  if (ascii(0, "hsqs") || ascii(0, "sqsh")) return "squashfs";
  if (ascii(0, "0707")) return "cpio";
  if (ascii(0, "!<arch>\n")) return "ar";
  if (ascii(257, "ustar")) return "tar";
  if (at(0, 0x45, 0x3d, 0xcd, 0x28) || at(0, 0x28, 0xcd, 0x3d, 0x45)) return "cramfs";
  if (ascii(0, "ANDROID!")) return "android-boot";
  if (ascii(0, "UF2\n")) return "uf2";
  if (at(0, 0x27, 0x05, 0x19, 0x56)) return "uimage";
  if (head.length > 1081 && head[1080] === 0x53 && head[1081] === 0xef) return "ext";
  if (ascii(32769, "CD001")) return "iso9660";
  if (head.length >= 512 && head[510] === 0x55 && head[511] === 0xaa) return "fat";
  // An Electron asar (api_minor 96): the size pickle, then the JSON header.
  if (at(0, 4, 0, 0, 0) && ascii(16, '{"files":')) return "asar";
  if (ascii(0, "PYZ") && head[3] === 0 && head[6] === 0x0d && head[7] === 0x0a) return "pyz";
  return "";
}
