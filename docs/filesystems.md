# Container file systems

Firmware rarely arrives as one ELF. It comes as a zip holding a tar.gz
holding a squashfs holding `/bin/busybox`, or an `.ipk` whose `data.tar.gz`
holds the program you want. revkit opens such containers as trees of
files, nested to any depth, as Ghidra's File System Browser does: browse
them, see what each file is, read and describe files, import the programs
in them (one, or a whole tree at once), and extract files to the daemon's
host. `api_minor` 48, feature `filesystems`.

- [Formats](#formats)
- [Nesting and paths](#nesting-and-paths)
- [What each file is](#what-each-file-is)
- [Importing](#importing) (and batch import from the command line)
- [Extracting](#extracting)
- [Security](#security)
- [Interfaces](#interfaces)
- [Libraries](#libraries)
- [Tests and fuzzing](#tests-and-fuzzing)
- [Known gaps](#known-gaps)

The code: `src/container` (the parsers, the decompressors, sessions; a
library with no dependency on the rest of revkit but the compression
libraries), `src/backend/filesystems.cc` (the service: sessions per caller,
listings, reads, info, extraction, the import plan), the import itself in
`src/backend/image_backend.cc` (`ImportFromFileSystem`, through
`ImportProgram`'s own code), `ui/src/ui/filesystem.ts` (the browser).

## Formats

Every format is recognised by its magic, never by its name
(`container::identify`), and read by a parser written for hostile input
(bounds-checked, with the limits below).

| Format | Recognised by | What is read |
| --- | --- | --- |
| zip (jar, apk, ...) | `PK\3\4` or an empty archive's `PK\5\6` | the central directory (zip64 too, a self-extractor's prefix skipped), Unix modes and symlinks, DOS times; members stored, deflated, bzip2, zstd or xz. Encrypted members and other methods (zip's own LZMA, deflate64) are listed with the reason they can't be read |
| tar | `ustar` at 257, or an old header whose checksum adds up | v7, ustar (with its prefix), GNU long names and links and base-256 numbers, pax `path`, `linkpath`, `size`, `mtime`, `uid`, `gid`; hard links, symlinks, devices. GNU sparse members are listed, not read |
| gzip | `1f 8b 08` | members concatenated; the inner name from the header (display only), else the outer name without `.gz` (`.tgz` gives `.tar`); the size from the trailer |
| bzip2 | `BZh1`..`BZh9` and a block magic | streams concatenated |
| xz | `fd 37 7a 58 5a 00` | streams concatenated, dictionaries up to 256 MiB |
| lzma | the `.lzma` header: lc/lp/pb `0x5d` (or another common one), a power-of-two-like dictionary, a plausible size | LZMA1 with its 13-byte header |
| zstd | `28 b5 2f fd` | frames concatenated, windows up to 128 MiB, the size from the frame header |
| lz4 | `04 22 4d 18` (frame), `02 21 4c 18` (legacy, the kernel's) | frames (linked and independent blocks, checksums skipped), skippable frames, the legacy format's 8 MiB blocks |
| cpio | `070701`, `070702` (newc), `070707` (odc), `c7 71` / `71 c7` (old binary) | every variant; archives concatenated (initramfs); newc hard links resolved to the entry holding the data |
| ar | `!<arch>\n` | static libraries and Debian packages (`.a`, `.deb`, new-style `.ipk`): GNU (`//`, `/<n>`) and BSD (`#1/<n>`) long names; symbol tables skipped; members of one name kept apart (`~2`) |
| ISO 9660 | `CD001` at 32769 | the primary volume with Rock Ridge (names, modes, owners, times, symlinks, continuation areas, relocated directories), else Joliet (UCS-2 names), else plain ISO names (versions dropped); multi-extent files; files map onto the image without a copy |
| squashfs | `hsqs` (`sqsh`, big-endian and pre-4.0, is recognised and refused with the reason) | 4.0 with gzip, lzma, lzo, xz, lz4 or zstd; basic and extended inodes; data blocks (sparse ones too) and fragments; hard links |
| ext2/3/4 | `ef 53` at 1080 with a sane superblock | read-only: 32- and 64-bit group descriptors, `meta_bg`, extent trees (unwritten extents read as zeros) and block maps (holes), inline data, fast and slow symlinks, directories read linearly (hashed ones too); a journal needing recovery is read as it is, with a warning; encrypted files listed, not read; files map onto the image without a copy |
| cramfs | `28 cd 3d 45` either byte order, at 0 or after 512 bytes | both byte orders, zlib blocks of 4 KiB, holes, extended block pointers (direct and uncompressed blocks) |
| FAT12/16/32 | a boot sector with a sane BPB and `55 aa` | the type from the cluster count, long names (checked against their short entry), 8.3 names with the lowercase flags, DOS times, cluster chains (loops and short chains refused) |
| uImage | `27 05 19 56` and a header CRC that matches | U-Boot legacy images: one member (decompressed when gzip, bzip2, lzma, lz4 or zstd), or a multi-file image's parts; the data CRC checked (a warning); the header's processor (as a language where its byte order is settled: ARM, AArch64, x86, x86-64, PowerPC) and load address on the member |
| Android boot image | `ANDROID!` | v0 to v4: kernel, ramdisk, second stage, recovery DTBO, DTB, the boot signature; v0-v2 load addresses on the members |
| UF2 | `UF2\n` and the block magics | blocks for the main flash, grouped by family (or by file name in a file container), one flat image per contiguous range (gaps under 64 KiB read as erased flash, 0xff), named `<family>@<address>.bin`, with the family's language (RP2040, RP2350, SAMD, nRF52, STM32, ESP32, i.MX RT, LPC55, GD32V) and the load address |
| partition tables | an MBR with sane entries, or `EFI PART` at 512 or 4096 | MBR primary and logical partitions (a loop in the chain refused), GPT entries with their names; each partition a file (`p1.img`, `p1-rootfs.img`), cut at the image's end |

Intel HEX and Motorola S-records are loaders already (`ImportOptions.raw_format`):
the browser shows them as `Intel HEX` and `Motorola S-record` and imports
them as raw images.

## Nesting and paths

A **session** is the outermost container (a file on the daemon's host, a
program's stored file, or bytes the client sent) and the containers mounted
inside it on demand. A **session path** names a file through every layer:
`!` separates the layers, and each layer is a path of names separated by
`/`:

```
/pkg/data.tar.gz!/data.tar!/usr/bin/tool
```

is `/usr/bin/tool` in the tar that is the gzip's one member, the gzip being
`/pkg/data.tar.gz` of the outermost container. A path ending in `!` names a
nested container's root (`/pkg/data.tar.gz!`). Names are percent-encoded
where they must be: `%`, `!`, `/`, control characters, DEL and bytes that
aren't UTF-8 (`%21`, `%FF`), so a member named `a!b` is `a%21b` and never a
layer boundary. Clients pass back the paths a listing gives them.

Names are normalized inside their container: empty components and `.`
dropped, `..` stopping at the container's root (an entry whose name went
above it is marked `renamed`, its note saying what it was stored as), a
file and a directory of one name kept apart with a `~2` suffix, a file
listed twice replaced by the later one (as extracting would).

A **container path** says where a file came from, in provenance:

```
zip://fw.zip!/pkg/data.tar.gz!/data.tar!/usr/bin/tool
```

the outermost format and file name, then the session path. A host
directory opened for batch import gives `file:///srv/fw/sub/x.zip!/a/b`.
Every program imported from a container records it
(`ProgramInfo.container_path`), and the program's record keeps it.

**Symbolic links** are followed inside their own container only: an
absolute target is from the container's root, `..` stops there, and a link
that leaves the container or loops (more than 40 hops) resolves to nothing
(`link_path` empty; reading it fails). Hard links (tar) name a path from the
archive's root.

## What each file is

A listing with `detect` reads each file's first 36 KiB (a head: a
compressed member is decompressed only that far) and says:

- `elf`: `ELF 64-bit LE x86-64 executable`, with the processor
  (`x86:LE:64`);
- `pe`: `PE x86-64 DLL`;
- `container`: a nested container's format (`gzip compressed`, `zip
  archive`): Open as file system;
- `raw`: Intel HEX, S-records, or data no header names;
- `text` (a script's `#!` line shown), `data` (Mach-O, DEX, a device tree,
  images and documents are named), `empty`.

Detection stops after about two seconds per listing
(`detect_incomplete`); `GetFileSystemFileInfo` describes any one file, with
its SHA-256, SHA-1, MD5 and first bytes.

## Importing

`ImportFromFileSystem` imports files as programs of a project: each through
`ImportProgram`'s own code (the loaders, debug info, analysis), with the
member's bytes, recording its container path. It needs editor of the
target project, not admin: the bytes come from a session the caller
already opened (as `PatchService.OpenOriginal` imports a stored file
again).

- **One file named alone** is imported whatever it is (a raw image needs
  `options.language_id`, as `ImportProgram` does).
- **Batch import**: directories (their files; `recursive`: everything
  below) and containers found on the way (`descend`) give their **programs
  only**: ELF and PE, and raw images whose header names their processor
  (`FileSystemEntry.language_id`). With `detect_raw` the daemon runs raw
  layout detection on other data files and imports those it identifies
  with high confidence (seconds per file). `programs_only` applies the
  same rule to files named directly.
- **Preview** (`preview`): what would be imported and why each other file
  is left out ("not a program (text)", "raw data whose processor no header
  names", "over the cap"); nothing is imported.
- **The cap** (`max_programs`, default 100, at most 1000): programs past it
  are listed as skipped and `capped` is set.
- **Folders**: into `folder_id`; `keep_folders` recreates the container's
  directories (and a nested container's name) as folders under it.

**From the command line**, on a `--project-dir` no daemon is using (as
`rk-daemon project export` and `import`):

```sh
rk-daemon project import-batch --project-dir ~/projects /srv/firmware --recursive --preview
rk-daemon project import-batch --project-dir ~/projects /srv/firmware --recursive --into fw \
    --folder /drops/2026-10 --keep-folders --max 500
rk-daemon project import-batch --project-dir ~/projects update.zip --into fw   # a container
```

`<path>` is a directory (walked without following symlinks out of it) or
a container; a plain file (an ELF) is imported by itself. Containers found
are looked inside unless `--no-descend`; `--detect-raw` runs raw layout
detection on other data; `--preview` says what would be imported; `--max`
caps the count (default 100); `--into` names the project (default
`default`, made if missing); `--folder` the folder (made if missing);
`--analyze` starts auto-analysis after each import. Each line says what
happened to one file and its container path; the exit status is 1 when an
import failed.

## Extracting

`ExtractFromFileSystem` writes files to a directory on the daemon's host
(admin), which must lie under a `--browse-root`; it is made if missing (its
parent must exist). A directory is extracted with everything below it.
Names are sanitized for the host: display text (valid UTF-8), `/`, `\` and
control characters replaced, `.` and `..` prefixed, at most 200 bytes.
Every directory is opened relative to the one above it (`openat`, never
following a symlink), files are created with `O_EXCL | O_NOFOLLOW` (mode
0644: execute bits are not kept), an existing file is replaced only with
`overwrite` and only when it is a regular file, and symlinks, devices,
pipes and sockets are skipped with the reason.

## Security

Every container is hostile input. The [threat model](security.md#threat-model)
puts malicious input files in scope for bounds-checked parsers; these
parsers are that, with these limits (`FileSystemLimits`; a request may lower
them, never raise them):

| Limit | Default | What it stops |
| --- | --- | --- |
| `max_file_bytes` | 1 GiB | one file's decompressed size: a bomb member |
| `max_total_bytes` | 4 GiB | decompressed data a session holds at once (mounted containers and files kept for reading; the least recently used go first) |
| `max_ratio` | 1000:1, past 64 MiB of output | decompression bombs that stay under the size limits |
| `max_depth` | 8 | nesting (42.zip's sixteen-way layers) |
| `max_entries` | 262,144 per container | listings that exhaust memory |
| symlink hops | 40 | link loops |
| directory depth | 256 | deep trees |

Besides those: nothing is decompressed until it is read (a listing reads
headers and, with `detect`, heads); decompressors' memory is bounded
(xz/lzma dictionaries 256 MiB, zstd windows 128 MiB); decompressed data
past 64 MiB goes to an unlinked temporary file, not memory; zip members
whose data overlaps another member's (the "overlapping files" zip bomb)
are refused; a session belongs to whoever opened it, at most 8 per caller
and 64 in all, closed after 30 minutes unused.

**Names never reach the host** except through extraction, which sanitizes
them as above. Traversal names (`../../etc/passwd`, `/etc/shadow`) are
normalized inside their container and marked.

**Who may do what** (`src/api/auth_policy.cc`):

| RPC | Needs |
| --- | --- |
| `OpenFileSystem` | viewer of the project for a program's stored file; admin for a host path, an upload or bytes (they read the host or bring in a file, as `ImportProgram` does) |
| `ListFileSystem`, `ReadFileSystemFile`, `GetFileSystemFileInfo`, `CloseFileSystem`, `ListFileSystems` | viewer, and the session's owner (anyone else gets `NOT_FOUND`; an admin reaches every session) |
| `ImportFromFileSystem` | editor of the target project |
| `ExtractFromFileSystem` | admin, under `--browse-root` |

## Interfaces

- **API**: `FileSystemService` in `proto/revkit/v1/filesystem.proto`
  ([api.md](api.md#container-file-systems)).
- **Python SDK**: `Client.open_filesystem(project, host_path=... |
  program_id=... | file=...)` returns a `FileSystem` with `list`,
  `entries`, `walk`, `read`, `info`, `import_` (also `import_files`),
  `extract` and `close` (a context manager); `Client.filesystems()` lists
  the caller's sessions.
- **TypeScript SDK**: `openFileSystem(rk, project, source)` returns a
  `FileSystemSession` (`list`, `entries`, `read`, `info`, `import`,
  `extract`, `close`); path helpers `encodeName`, `displayPath`,
  `joinPath`, `parentPath`, `pathLayers`; `looksLikeContainer` for a
  client's own magic check.
- **MCP**: `open_filesystem`, `list_filesystem`, `read_filesystem_file`,
  `filesystem_file_info`, `import_from_filesystem`, `close_filesystem`.
- **`revkit.script`**: `open_filesystem(...)` (the current program's
  stored file by default) and `import_from_filesystem(fs, paths, ...)`,
  which imports with the run's provenance.
- **The UI**: File → Open file system…, and "Open as file system" in the
  Open dialog ([ui.md](ui.md#file-system-browser)).

## Libraries

zlib (already a dependency), liblzma (xz and .lzma) and libbz2, linked
from the system and carried in the bundle's `lib/revkit` like zlib
([packaging.md](packaging.md)); zstd from the copy wasmtime's static
library already carries (the system's `libzstd` in a build without
plugins); LZ4 (frame, legacy and block) and LZO1X
are decoded by revkit's own code (`src/container/decompress.cc`, from the
formats' public descriptions), as no library for them is on the `.deb`'s
promise. Their licenses are in [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).

## Tests and fuzzing

- `revkit_container_tests` (`src/container/tests`): per format, fixtures
  made at test time with the standard tools (`zip`, `tar`, `gzip`,
  `bzip2`, `xz`, `zstd`, `lzma`, `lz4`, `cpio`, `ar`, `xorriso`,
  `mksquashfs` with all six compressors, `mke2fs -d` for ext2, ext3, ext4,
  inline data and 64-bit `meta_bg`, `mkfs.cramfs` in both byte orders,
  `mkfs.fat` for FAT12, 16 and 32) or Python where a tool is missing
  (FAT's files, as there is no mtools here; uImage, Android boot, UF2, MBR
  and GPT images; a test without its tool skips itself with a message);
  nesting four and five layers deep by magic alone (an `.ipk` holding a
  `data.tar.gz` holding a squashfs); the firmware corpus's U-Boot and an
  ELF wrapped as a vendor ships them (a uImage in a tar.gz, a squashfs in a
  zip; `RK_FIRMWARE_CORPUS` or `out/firmware-corpus`, skipped without it);
  the hostile cases: a zip bomb (size, ratio and session budget),
  overlapping zip members, traversal names, symlink loops and escapes,
  names with control bytes and invalid UTF-8, truncated and corrupted
  archives and file system images (squashfs, ext4, cramfs, ISO, cpio:
  truncations and 200 flipped bytes each), a host directory whose symlinks
  point out.
- `python_sdk` (`sdk/python/tests/test_filesystems.py`): the service end to
  end, MCP, `revkit.script`, extraction, the roles, and a batch import
  descending into a squashfs inside a zip and taking a UF2 image as a raw
  program at its load address.
- `ts_sdk_filesystems` (`sdk/ts/test/filesystems.ts`).
- `ui_e2e` (`ui/e2e/filesystems.ts`): browse, open nested containers in
  place, Info, import and open a program; Open as file system from the Open
  dialog; batch import with preview and cap.
- **Fuzzing** (with `-DREVKIT_FUZZ=ON` and clang; the bug scrub,
  [roadmap.md](roadmap.md)): `container_<format>_fuzzer` for every format,
  and `container_codecs_fuzzer` for the LZ4 and LZO1X block decoders.

## Known gaps

- Formats not read: 7z, rar, cab, dmg, HFS+, NTFS, YAFFS2, UBI/UBIFS,
  JFFS2, romfs, Android sparse images, FIT images, TRX, UEFI volumes;
  squashfs before 4.0; zip's own LZMA and deflate64; tar's GNU sparse
  members; encrypted zip members and fscrypt files; uImage LZO (lzop)
  payloads. cramfs is read with 4 KiB blocks (an image made with another
  `-b` fails to decompress).
- ext: the journal is not replayed.
- A browser's listing shows up to 2,000 entries per directory.
