# Container file systems

Firmware rarely arrives as one ELF. It comes as a zip holding a tar.gz
holding a squashfs holding `/bin/busybox`, or an `.ipk` whose `data.tar.gz`
holds the program you want. revkit opens such containers as trees of
files, nested to any depth, as Ghidra's File System Browser does: browse
them, see what each file is, read and describe files, import the programs
in them (one, or a whole tree at once), and extract files to the daemon's
host. `api_minor` 48, feature `filesystems`; packed executables
(PyInstaller, Electron asar, pkg, nexe, Node SEA, Bun) and Lua chunks in
firmware from `api_minor` 96, feature `packed-executables`.

- [Formats](#formats)
- [Packed executables](#packed-executables)
- [Nesting and paths](#nesting-and-paths)
- [What each file is](#what-each-file-is)
- [Content kinds](#content-kinds)
- [Importing](#importing) (and batch import from the command line)
- [Extracting](#extracting)
- [Security](#security)
- [Interfaces](#interfaces)
- [Libraries of imported programs](#libraries-of-imported-programs)
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
| Electron asar | the size pickle (4), sizes that agree, `{"files":` | the JSON header's files, directories, links (from the archive's root) and executable bits; `unpacked` files read from `<archive>.unpacked/` beside it when the archive is inside a container or a host directory (else listed, unreadable); `.js` members `js-source` |
| PyInstaller | its cookie (`MEI\014\013\012\013\016`) at the end of the ELF section `pydata`, or in the file's last MiB (appended: Windows, macOS, older Linux builds) | the CArchive's table of contents: scripts and bootstrap modules as `.pyc` files with the header restored (the PYZ's magic number, else the release's of the cookie's Python version; modules that kept their own header, PyInstaller 5.2 and older, left as they are), binaries, data files, zips, splash resources, links; runtime options counted; the 24-byte cookie of 2.0 too |
| PyInstaller PYZ | `PYZ\0` and a known pyc magic | the marshalled table of contents (a list, or 2.x's dict), each module as `a/b.pyc` and each package as `a/b/__init__.pyc` with its header restored, namespace packages as directories; entries encrypted with `--key` (before 6.0) listed, not read |
| Node.js SEA | a `NODE_SEA_BLOB` ELF note, PE `RCDATA` resource or Mach-O `NODE_SEA,__NODE_SEA_BLOB` section, with the blob's magic `0x0143da20` | the main script (by its `code_path`'s name), or the startup snapshot; the V8 code cache (`useCodeCache`); the assets under `assets/`; `execArgv` in the description. Every layout from Node 20.0 to 26 (picked by which one parses to the blob's end) |
| pkg | its prelude ending the file (or, on macOS, before the signature) | the virtual file system: files as source, compiled ones (`STORE_BLOB`) as `<name>.jsc` V8 code caches, directories, links; gzip and zstd stripes decompressed (Brotli ones listed, unreadable); keys through pkg's dictionary when compressed; the entry point in the description |
| nexe | `<nexe~~sentinel>` and two doubles in the last 16000 bytes | the launcher with the bundled entry script (`nexe-launch.js`), the resources by `process.__nexe`'s index (3 and 4), or as a zip (5) |
| Bun | `\n---- Bun! ----\n` ending the module graph: appended (with the file's size after it), or in the `.bun` section (ELF, by its virtual address; PE), or Mach-O's `__BUN,__bun` | each module by its `/$bunfs/root/` name, its JavaScriptCore bytecode beside it (`.jsc-bytecode`); the record layouts of 1.0 to 1.3 (the one whose names all parse) |
| a zip appended to an executable | an end record in the last 64 KiB of an ELF, PE or Mach-O, its central directory in the file | as zip, the prefix skipped (py2exe's library, self-extracting archives) |
| Lua chunks | a file no other format names, with a `\x1bLua` or `\x1bLJ` header that parses and functions that walk to their end in its first 256 MiB | each chunk as `<kind>@<offset>.luac` (`lua-5.4@0x1a2b0.luac`), cut to its exact length (Lua 5.5: to the next chunk, as its dump isn't walked); LuaJIT prototypes checked against their own sizes |

Intel HEX and Motorola S-records are loaders already (`ImportOptions.raw_format`):
the browser shows them as `Intel HEX` and `Motorola S-record` and imports
them as raw images.

## Packed executables

A program packed with its scripts (PyInstaller, pkg, nexe, Node's SEA,
Bun) is a program and a container at once. It stays a program: its
listing entry is `elf` or `pe` (bold, imported by a batch import), and
its `container_format` names the packer's archive, so the browser opens it
in place and Info shows the archive (`api_minor` 96, feature
`packed-executables`). A listing looks for these only in files whose bytes
are stored plainly (a decompressed member's bytes would have to be
decompressed in full); Info always looks. `ProgramInfo.payload_format`
says the same of an imported program, and `OpenFileSystem` with its
`program_id` opens the archive; the Open dialog's details have a **Packed**
line with **Open as file system**, and the import toasts it.

What they hold comes out as files a decompiler takes, by [content
kind](#content-kinds): PyInstaller's scripts and modules as `.pyc` files
whose header is restored (they run as extracted), JavaScript as source
(`js-source`), pkg's compiled scripts and Node's code caches as
`v8-cache`, Bun's bytecode as `jsc-bytecode`.

Not read yet:

- **Deno** (`deno compile`): Deno 1.x appends an eszip and its metadata
  behind a `d3n0l4nd` trailer; Deno 2 puts a section `d3n0l4nd` (libsui:
  an ELF note or trailer, a PE resource, a Mach-O `__SUI` section) holding
  the metadata, an npm snapshot, the remote modules and a virtual file
  system whose layout changed in 2.1, 2.2, 2.4, 2.6 and 2.9. Its files are
  plain once found; the work is the six layouts.
- **py2exe**'s `PYTHONSCRIPT` resource (a marshalled list of code objects,
  the main scripts): its library (an appended zip, or `library.zip` beside
  it) opens, the scripts don't yet.
- **cx_Freeze** needs nothing more: `lib/library.zip` is a zip of `.pyc`
  files, and an older build's appended zip opens as above.
- Nuitka's onefile payload, AutoIt and AutoHotkey scripts in resources,
  .NET single-file bundles and embedded assemblies.
- Lua chunks embedded in an ELF or PE (only files no format names are
  searched), Lua 5.0, modified Lua VMs (another format byte).

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
- `macho`: `Mach-O 64-bit arm64 executable` (with the processor), or
  `Mach-O universal (x86_64, arm64)` (api_minor 90; [macho.md](macho.md));
  a batch import's programs include them;
- `bytecode` (`api_minor` 95): a `.pyc` (`Python 3.12 bytecode (magic
  3531)`), a Lua or LuaJIT chunk (`Lua 5.4 chunk (64-bit integers, 64-bit
  floats)`), a Java class (`Java class (Java 21, class file 65.0)`), DEX,
  WebAssembly, Hermes, a V8 code cache, Ruby `YARB`, PHP opcache, Erlang
  BEAM, a JerryScript snapshot, each with its [content kind](#content-kinds);
- `text` (a script's `#!` line shown), `data` (a device tree, images and
  documents are named), `empty`.

A PE's description says when it is a .NET assembly (`PE x86 DLL, .NET
assembly (IL-only, metadata v4.0.30319)`), and a zip's when its first
members make it a Java archive or an Android package (`zip archive
(Android package)`).

Detection stops after about two seconds per listing
(`detect_incomplete`); `GetFileSystemFileInfo` describes any one file, with
its SHA-256, SHA-1, MD5 and first bytes.

## Content kinds

`api_minor` 95, feature `content-kinds`. Each file of a listing has a
`content_kind` when it is a script or bytecode: what a decompiler for that
language would take it as, `family:version` where the header says the
version. The external decompiler providers
([bytecode-lifting.md](bytecode-lifting.md#plan), step 2) dispatch on the
family, the part before the colon. The file's own header decides when it
has one (a listing with `detect`); otherwise the container says, by the
member's name or role (an asar's `.js` files, a packer's main script).

| Kind | What | From |
| --- | --- | --- |
| `pyc:<major>.<minor>` | a CPython `.pyc`, 2.0 to 3.16 (`pyc:2.7`, `pyc:3.12`) | the magic number (CPython's table; from 3.11, 3.n takes 2900 + 50n onwards) and a code object after the 8-, 12- or 16-byte header |
| `lua:<major>.<minor>` | a Lua 5.1 to 5.5 chunk (`lua:5.4`) | `\x1bLua`, the version byte, format 0, and sizes that make sense (5.3 and later: `LUAC_INT` and `LUAC_NUM` read back) |
| `luajit:2.0`, `luajit:2.1` | LuaJIT bytecode | `\x1bLJ`, version 1 or 2, known flags |
| `java-class:<version>` | a JVM class file (`java-class:8`, `java-class:21`; `1.1` to `1.4` for the oldest) | `0xcafebabe` that isn't a universal Mach-O, the major version, a constant pool |
| `jar`, `apk` | a zip that is a Java archive or an Android package | its first members (`META-INF/MANIFEST.MF` and classes; `AndroidManifest.xml`, `classes.dex`, `resources.arsc`) |
| `dex:<version>`, `odex:<version>` | Dalvik bytecode (`dex:035` to `dex:041`) | `dex\n` and three digits |
| `wasm`, `wasm-component` | a WebAssembly module, a component | `\0asm` and the version |
| `hermes:<version>` | Hermes bytecode, React Native (`hermes:96`) | the 8-byte magic (the delta one too) and the version |
| `v8-cache` | a V8 code cache: `vm.Script`'s cached data, bytenode's `.jsc` | the `0xC0DE....` magic and a payload length that fills the file |
| `dotnet:il`, `dotnet:mixed` | a .NET assembly, IL-only or mixed-mode | the PE's CLR header |
| `yarb:<major>.<minor>`, `php-opcache`, `beam`, `jerryscript:<version>` | Ruby instruction sequences, PHP opcache files, Erlang BEAM modules, JerryScript snapshots | their magics |
| `js-source`, `python-source`, `lua-source` | a script, by its `#!` interpreter (node, deno, bun; python; lua, luajit) | the first line |
| `js-source`, `ts-source` | a packer's script: an asar's, pkg's, nexe's, a SEA's or Bun's `.js` (`.mjs`, `.cjs`) and `.ts` members | the container |
| `v8-snapshot` | a SEA's startup snapshot | the container |
| `jsc-bytecode` | Bun's JavaScriptCore bytecode cache | the container |

Not named, because their headers aren't reliable: QuickJS bytecode (its
first byte is a version number), Lua 5.0 and modified Lua VMs (a format
byte other than 0).

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

## Libraries of imported programs

`api_minor` 79, feature `library-roots`. With `ImportOptions.import_libraries`
(the batch dialog's **Also import the libraries they need, from this file
system**), the shared libraries each imported program needs that the
project has no program for are looked for in the file system it came from,
not on the daemon's host: in the container layer the program is in (a
squashfs's root, say), in order

1. `library_search_paths`, as paths inside that layer (`/opt/vendor/lib`);
2. the program's own directory (a PE's DLLs beside the exe);
3. its `DT_RUNPATH` (else `DT_RPATH`): `$ORIGIN` its directory, absolute
   entries from the layer's root;
4. the directories the layer's `/etc/ld.so.conf` names, with one level of
   `include` (`/etc/ld.so.conf.d/*.conf`);
5. `/lib` and `/usr/lib` with their multiarch (`arm-linux-gnueabihf`) and
   `lib64`/`lib32` forms, and `/usr/local/lib`.

The first file of the name whose header has the program's format, word
size and machine (and byte order, for ELF) is imported from its bytes,
with its container path, into the folder of the program that needs it, as
an item with `library_of` set; then its own libraries, to `library_depth`
levels (0: 2), at most 64 per import. Symbolic links are followed inside
the layer only, as everywhere in a session, so `libc.so.6 ->
/lib/libc-2.31.so` resolves inside the image. A batch import resolves the
programs it imports first, so a library the batch brings (by name, or by
its `DT_SONAME`) is linked rather than imported twice. The response lists
what was found nowhere (`libraries_not_found`, with who needs it) and
libraries that failed to import (`library_warnings`).

A root file system already extracted on the daemon's host is the same idea
for `ImportProgram` by path: see [api.md](api.md#libraries)
(`ImportOptions.library_root`, found by itself under a `--browse-root`).

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
- `revkit_container_tests` `ContainerPackers.*` (`src/container/tests/packers_test.cc`):
  every packer's container, on the formats as
  `tests/data/bytecode/make_packed.py` writes them onto a copy of
  `/bin/true` (a CArchive with a PYZ, pkg plain and gzip, nexe 4 and 5,
  Bun, an appended zip, Lua in firmware with decoys), a real SEA blob from
  `node --experimental-sea-config` put in an ELF note as postject does,
  a real PyInstaller one-file build (its script runs as extracted) and
  Lua chunks from lupa carved out of noise, all where the tools are here;
  an asar with unpacked files, read through a host directory; truncations
  and flipped bytes. Checked by hand against real tools (2026-10-18):
  `@electron/asar`, `postject` on Node 24, `@yao-pkg/pkg` 6.23 (plain and
  `--compress GZip`), PyInstaller 6.22.
- `revkit_container_tests` `ContainerBytecode.*` (`src/container/tests/bytecode_test.cc`):
  every content kind, on real files where the toolchain is here (a `.pyc`
  from `py_compile`, a class and a jar from `javac`, a V8 code cache from
  `node`, an assembly from the dotnet SDK, Lua 5.1 to 5.5 and LuaJIT 2.0
  and 2.1 chunks from the interpreters lupa bundles,
  `tests/data/bytecode/make_lua_chunks.py`: each walked to its exact
  length, and truncations refused) and on headers written by the test
  otherwise (the pyc magic table from 2.7 to 3.15, Lua's sizes, DEX, wasm,
  Hermes, YARB, BEAM, opcache).
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
  `container_codecs_fuzzer` for the LZ4 and LZO1X block decoders, and
  `container_bytecode_fuzzer` for the bytecode headers (guess, a PE's CLR
  header, a Lua chunk's header and walk); the packers' formats each have
  theirs (`container_asar_fuzzer`, `_pyinstaller_`, `_pyz_` (with the
  marshal reader), `_lua_chunks_`, `_node_sea_`, `_pkg_` (with the JSON
  reader), `_nexe_`, `_bun_`).

## Known gaps

- Formats not read: 7z, rar, cab, dmg, HFS+, NTFS, YAFFS2, UBI/UBIFS,
  JFFS2, romfs, Android sparse images, FIT images, TRX, UEFI volumes;
  squashfs before 4.0; zip's own LZMA and deflate64; tar's GNU sparse
  members; encrypted zip members and fscrypt files; uImage LZO (lzop)
  payloads. cramfs is read with 4 KiB blocks (an image made with another
  `-b` fails to decompress).
- ext: the journal is not replayed.
- Packers not read yet: Deno executables, py2exe's `PYTHONSCRIPT`,
  Nuitka onefile, AutoIt and AutoHotkey scripts, .NET bundles
  ([Packed executables](#packed-executables)). pkg's Brotli-compressed
  files are listed, not read (no Brotli decoder). PyInstaller's `--key`
  encryption (before 6.0) isn't undone. An asar opened by itself can't
  read its `unpacked` files: open the folder holding both.
- A browser's listing shows up to 2,000 entries per directory.
