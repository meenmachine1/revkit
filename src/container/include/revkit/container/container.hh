// Container file systems: archives (zip, tar, cpio, ar, ISO 9660),
// single-file compression (gzip, xz, bzip2, lz4, zstd, lzma), file system
// images (squashfs, ext2/3/4, cramfs, FAT, and the flash file systems JFFS2,
// UBI/UBIFS and YAFFS2) and firmware packages (uImage, Android boot and
// sparse images, UF2, TRX, device trees and FIT, Intel HEX and S-records),
// browsed as trees of files, nested to any depth (docs/filesystems.md).
//
// Everything here reads hostile input. Every parser is bounds-checked and
// throws container::Error on malformed data; decompression is bounded by
// Limits (a file's size, the bytes a session holds, the compression ratio),
// listings by a member count, nesting by a depth. Names are display-only:
// nothing here touches the host's file system except DirFileSystem (a host
// directory opened as the outermost layer, read without following
// symlinks) and the temporary files large decompressed members spill to.
#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::container {

// Malformed or unsupported input.
class Error : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

// A limit was reached (a decompression bomb, too many members, too deep).
class LimitError : public Error {
 public:
  using Error::Error;
};

struct Limits {
  // One file's contents once decompressed.
  std::uint64_t max_file_bytes = 1ull << 30;
  // Decompressed bytes a session holds at once (members materialized for
  // reading, nested containers mounted).
  std::uint64_t max_total_bytes = 4ull << 30;
  // Containers inside containers: the outermost is depth 1.
  std::uint32_t max_depth = 8;
  // Entries (files, directories, links) in one container.
  std::uint32_t max_entries = 262144;
  // Decompressed size over compressed size, checked once the output passes
  // ratio_floor: real data seldom passes 1000:1 at that size, bombs do.
  std::uint64_t max_ratio = 1000;
  std::uint64_t ratio_floor = 64ull << 20;
  // Symbolic links followed to reach one file.
  std::uint32_t max_symlink_hops = 40;
  // Directory nesting inside one container.
  std::uint32_t max_dir_depth = 256;
  // Decompressed data larger than this goes to an unlinked temporary file
  // instead of memory.
  std::uint64_t memory_threshold = 64ull << 20;
};

// Bytes a session holds, against Limits::max_total_bytes. Shared by every
// Source a session materializes; each releases its share when destroyed.
class Budget {
 public:
  explicit Budget(std::uint64_t limit) : limit_(limit) {}
  // Throws LimitError when n more bytes would pass the limit.
  void charge(std::uint64_t n);
  void release(std::uint64_t n) { used_.fetch_sub(n); }
  std::uint64_t used() const { return used_.load(); }
  std::uint64_t limit() const { return limit_; }

 private:
  std::uint64_t limit_;
  std::atomic<std::uint64_t> used_{0};
};

// Everything a parser needs besides the bytes.
struct Context {
  Limits limits;
  std::shared_ptr<Budget> budget = std::make_shared<Budget>(Limits{}.max_total_bytes);
  // Polled during long work (decompression); true stops it with Error.
  std::function<bool()> cancelled = [] { return false; };
  void check_cancelled() const;
};

// Random-access bytes: a host file, memory, a slice of another source, or
// decompressed data. Reads are thread-safe.
class Source {
 public:
  virtual ~Source() = default;
  virtual std::uint64_t size() const = 0;
  // Reads up to out.size() bytes at `offset`; fewer only at the end.
  virtual std::size_t read(std::uint64_t offset, std::span<std::byte> out) const = 0;
  // The bytes, when they are in memory (empty otherwise).
  virtual std::span<const std::byte> view() const { return {}; }

  // Exactly n bytes at offset, or Error naming `what`.
  std::vector<std::byte> read_exact(std::uint64_t offset, std::uint64_t n, std::string_view what) const;
  // At most n bytes from the start.
  std::vector<std::byte> head(std::uint64_t n) const;
};

std::shared_ptr<Source> memory_source(std::vector<std::byte> bytes);
// A host file, read with pread; the size is fixed when opened.
std::shared_ptr<Source> file_source(int fd_owned, std::uint64_t size);
std::shared_ptr<Source> open_host_file(const std::string &path);
// [offset, offset + size) of `base`; Error when it doesn't fit.
std::shared_ptr<Source> slice(std::shared_ptr<const Source> base, std::uint64_t offset, std::uint64_t size);

// Collects decompressed output with the limits applied: at most `max`
// bytes (Limits::max_file_bytes by default), charged to the budget, spilled
// to a temporary file past Limits::memory_threshold. `stop_after` ends the
// output early without error (reading a file's head): full() turns true
// and decoders stop.
class Sink {
 public:
  explicit Sink(const Context &ctx, std::uint64_t stop_after = UINT64_MAX);
  ~Sink();
  Sink(const Sink &) = delete;
  Sink &operator=(const Sink &) = delete;

  void append(std::span<const std::byte> data);
  // Compressed bytes read so far, for the ratio check.
  void consumed(std::uint64_t compressed_total);
  bool full() const { return size_ >= stop_after_; }
  std::uint64_t size() const { return size_; }
  std::shared_ptr<Source> finish();

 private:
  void spill();
  void check_ratio() const;
  const Context &ctx_;
  std::uint64_t stop_after_;
  std::uint64_t max_;
  std::uint64_t size_ = 0;
  std::uint64_t compressed_ = 0;
  std::uint64_t charged_ = 0;
  std::vector<std::byte> mem_;
  int fd_ = -1;
};

// ---- names and paths ---------------------------------------------------

// A member's name as display text: valid UTF-8, with invalid bytes and
// control characters shown as U+FFFD.
std::string display_name(std::string_view raw);
// One path component for the API: raw bytes with '%', '!', '/', control
// characters, DEL and bytes that aren't UTF-8 percent-encoded ("%21"), so
// '/' only separates components and '!' only separates nested layers.
std::string encode_component(std::string_view raw);
// Back to raw bytes. Error on a malformed escape.
std::string decode_component(std::string_view encoded);
// "/a/b" (encoded components) to raw components; "", "/" are the root.
std::vector<std::string> split_path(std::string_view encoded);
std::string join_path(const std::vector<std::string> &raw_components);

// ---- entries ------------------------------------------------------------

enum class Kind : std::uint8_t { file, directory, symlink, char_device, block_device, fifo, socket, hardlink, other };
std::string_view name(Kind k);

struct Entry {
  std::string name;       // raw bytes ("" for the root)
  std::uint32_t parent = 0;
  Kind kind = Kind::file;
  std::uint64_t size = 0;           // bytes of content (files), or of the target (links)
  std::uint32_t mode = 0;           // permission bits (07777)
  bool has_mode = false;
  std::uint32_t uid = 0, gid = 0;
  bool has_owner = false;
  std::int64_t mtime = 0;           // seconds since 1970
  bool has_mtime = false;
  std::string link_target;          // symlinks (and hard links: the path inside the container)
  std::uint64_t stored_size = 0;    // bytes in the container (compressed), when known
  std::string note;                 // why it can't be read ("encrypted"), or what it is
  // What the container says the file is, when its header can't: a
  // packer's script ("js-source"), or bytecode it stores bare. The content
  // kinds are listed in docs/filesystems.md; a guess from the file's own
  // header (Guess::content_kind) wins over this.
  std::string content_kind;
  bool renamed = false;             // its name had "..", was absolute, or clashed with a sibling
  // A firmware package's member: the language its header names (a full
  // Ghidra id, when the header settles it) and where it loads.
  std::string language;
  std::optional<std::uint64_t> load_address;
  // The format's own locators (an offset, an inode, an index).
  std::uint64_t loc0 = 0, loc1 = 0, loc2 = 0;
  std::vector<std::uint32_t> children;  // directories, by name
};

// One container, listed in full when opened. entries()[0] is the root
// directory. Immutable once built; open() is thread-safe.
class FileSystem {
 public:
  virtual ~FileSystem() = default;

  const std::string &format() const { return format_; }
  // A line saying what it is: "squashfs 4.0, xz, 1214 files".
  const std::string &description() const { return description_; }
  const std::vector<std::string> &warnings() const { return warnings_; }
  const std::vector<Entry> &entries() const { return entries_; }
  const Entry &entry(std::uint32_t i) const { return entries_.at(i); }
  // A display path of an entry ("/bin/busybox"), encoded components.
  std::string path_of(std::uint32_t i) const;
  // Raw components of an entry's path.
  std::vector<std::string> components_of(std::uint32_t i) const;

  // The entry at raw components, following symbolic links on the way
  // (and at the end when follow_last), inside the container only: an
  // absolute target is from the container's root, ".." stops at the root.
  // nullopt: no such entry. Error: a symlink loop or too many hops.
  std::optional<std::uint32_t> find(const std::vector<std::string> &components, bool follow_last,
                                    std::uint32_t max_hops = 40) const;
  // A symlink's (or hard link's) target entry, as find() resolves it.
  std::optional<std::uint32_t> resolve_link(std::uint32_t link, std::uint32_t max_hops = 40) const;

  // A regular file's contents (a hard link's: its target's). Error when it
  // can't be read (encrypted, an unsupported method, corrupt).
  virtual std::shared_ptr<Source> open(std::uint32_t entry, const Context &ctx) const = 0;
  // At most n bytes of its start, without decompressing the rest where the
  // format allows.
  virtual std::vector<std::byte> head(std::uint32_t entry, std::uint64_t n, const Context &ctx) const;
  // The file's bytes are stored as they are (open() maps them, nothing is
  // decompressed): reading all of it is cheap.
  virtual bool stored_plain(std::uint32_t) const { return false; }

 protected:
  friend class TreeBuilder;
  // Adds a warning; past kMaxWarnings, one line says the rest were dropped
  // (a hostile image can repeat one problem per block or entry).
  static constexpr std::size_t kMaxWarnings = 1000;
  void warn(std::string w) {
    if (warnings_.size() < kMaxWarnings) warnings_.push_back(std::move(w));
    else if (warnings_.size() == kMaxWarnings) warnings_.push_back("more warnings were dropped");
  }
  std::string format_;
  std::string description_;
  std::vector<std::string> warnings_;
  std::vector<Entry> entries_;
};

// Builds a FileSystem's tree: from paths (archives list "a/b/c") or from
// a parent and a name (file systems walk directories). Normalizes names
// ("." and empty components dropped, ".." stops at the root, which marks
// the entry renamed), makes missing parent directories, keeps one entry
// per name (a later file replaces an earlier one, as extracting would;
// a name clash between kinds gets a "~2" suffix), sorts children, and
// enforces Limits::max_entries and max_dir_depth.
class TreeBuilder {
 public:
  TreeBuilder(FileSystem &fs, const Limits &limits);
  ~TreeBuilder();
  TreeBuilder(const TreeBuilder &) = delete;
  TreeBuilder &operator=(const TreeBuilder &) = delete;
  // Adds or replaces the entry at `path` (separators '/'; leading '/' and
  // "./" ignored). Returns its index.
  std::uint32_t add_path(std::string_view path, Entry e);
  // Adds a child of a directory; name must not be empty, "." or "..".
  std::uint32_t add_child(std::uint32_t parent, Entry e);
  // A directory at `path`, made if missing.
  std::uint32_t directory(std::string_view path);
  std::size_t count() const;
  // Sorts children; call once all entries are in.
  void finish();
  // Two files of one name are both kept (the later renamed "~2"), not
  // replaced: ar archives of objects that share a name.
  bool keep_duplicates = false;

 private:
  std::uint32_t child_named(std::uint32_t parent, const std::string &name) const;
  std::uint32_t depth_of(std::uint32_t i) const;
  FileSystem &fs_;
  const Limits &limits_;
  struct Index;
  std::unique_ptr<Index> ix_;
};

// ---- recognition --------------------------------------------------------

// The container format a file is: what its first bytes (and size) say,
// "zip", "tar", "gzip", "squashfs", ..., else what identify_payload finds
// in the rest of it; "" when none.
std::string identify(const Source &src);
// The same from a file's first kIdentifyBytes (or all of it) and its size.
constexpr std::uint64_t kIdentifyBytes = 36864;
std::string identify_head(std::span<const std::byte> head, std::uint64_t size);
// What a file is, for a listing: "ELF 32-bit LE ARM executable", "PE
// x86-64 DLL", "squashfs file system", "Intel HEX", "text", "data". From
// the first bytes only (pass at least 4 KiB where there are).
struct Guess {
  std::string description;   // as above
  // "elf", "pe", "macho", "container", "raw", "text", "data", "empty", or
  // "bytecode" (a .pyc, a Lua chunk, a Java class, DEX, WebAssembly, ...)
  std::string kind;
  std::string format;        // "elf", "pe", "macho", a container format, "ihex", "srec", "uf2", "pyc", ...
  std::string processor;     // "ARM:LE:32", "x86:LE:64", ... when the header names it
  // What a decompiler for scripts and bytecode would take it as, with the
  // version where the header says: "pyc:3.12", "lua:5.4", "luajit:2.1",
  // "java-class:21", "dex:035", "wasm", "hermes:96", "dotnet:il", "jar",
  // "apk", "js-source", ... (docs/filesystems.md lists them). Empty for
  // native programs and plain data.
  std::string content_kind;
  // A packer's archive the file carries (a program: "pyinstaller",
  // "node-sea", ...; data: "lua-chunks"), when it was looked for
  // (identify_payload): Open as file system opens it.
  std::string payload;
};
Guess guess(std::span<const std::byte> head, std::uint64_t size, std::string_view container_format = {});

// What a file whose head names no container carries, found by reading
// more of it (its end, its sections, notes or resources; at most its first
// 256 MiB): a packer's archive appended to or embedded in an executable
// ("pyinstaller", "node-sea", "pkg", "nexe", "bun", "zip" for an appended
// zip: py2exe's library, a self-extractor), or Lua chunks in a firmware
// image or any other file ("lua-chunks"). "" when none.
// docs/filesystems.md, "Packed executables".
std::string identify_payload(const Source &src, const std::function<bool()> &cancelled = {});

// Opens `src` as a container of the given format (identify()'s answer).
// `name` is the file's own name, for single-file formats' member names.
std::shared_ptr<FileSystem> open_format(const std::string &format, std::shared_ptr<const Source> src,
                                        std::string_view name, const Context &ctx);
// identify() then open_format(); nullptr when it isn't a container.
std::shared_ptr<FileSystem> open_container(std::shared_ptr<const Source> src, std::string_view name,
                                           const Context &ctx);
// Every format open_format() knows, for docs and tests.
std::vector<std::string> formats();

// A host directory as the outermost layer (batch import): regular files,
// directories and symlinks, read without following any symlink (a link to
// a file outside the directory is listed, never read). Listing stops at
// Limits::max_entries.
std::shared_ptr<FileSystem> open_host_directory(const std::string &path, const Context &ctx);

}  // namespace revkit::container
