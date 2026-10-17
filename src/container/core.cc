// Sources, the sink that bounds decompression, names and paths, and the
// tree every format builds.
#include "revkit/container/container.hh"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <filesystem>
#include <unordered_map>

namespace revkit::container {

namespace {

std::string mib(std::uint64_t n) {
  if (n >= (1ull << 30) && n % (1ull << 30) == 0) return std::to_string(n >> 30) + " GiB";
  if (n >= (1ull << 20)) return std::to_string(n >> 20) + " MiB";
  return std::to_string(n) + " bytes";
}

// Memory owned by the source, its size charged to a budget until freed.
class MemorySource final : public Source {
 public:
  MemorySource(std::vector<std::byte> bytes, std::shared_ptr<Budget> budget, std::uint64_t charged)
      : bytes_(std::move(bytes)), budget_(std::move(budget)), charged_(charged) {}
  ~MemorySource() override {
    if (budget_) budget_->release(charged_);
  }
  std::uint64_t size() const override { return bytes_.size(); }
  std::size_t read(std::uint64_t offset, std::span<std::byte> out) const override {
    // A zero-length read (read_exact of 0 bytes) has a null buffer, which
    // memcpy may not be given even for 0 bytes (UBSan; extract_fuzzer).
    if (offset >= bytes_.size() || out.empty()) return 0;
    const std::size_t n = static_cast<std::size_t>(std::min<std::uint64_t>(out.size(), bytes_.size() - offset));
    std::memcpy(out.data(), bytes_.data() + offset, n);
    return n;
  }
  std::span<const std::byte> view() const override { return bytes_; }

 private:
  std::vector<std::byte> bytes_;
  std::shared_ptr<Budget> budget_;
  std::uint64_t charged_;
};

class FileSource final : public Source {
 public:
  FileSource(int fd, std::uint64_t size, std::shared_ptr<Budget> budget = nullptr, std::uint64_t charged = 0)
      : fd_(fd), size_(size), budget_(std::move(budget)), charged_(charged) {}
  ~FileSource() override {
    ::close(fd_);
    if (budget_) budget_->release(charged_);
  }
  std::uint64_t size() const override { return size_; }
  std::size_t read(std::uint64_t offset, std::span<std::byte> out) const override {
    if (offset >= size_) return 0;
    std::size_t want = static_cast<std::size_t>(std::min<std::uint64_t>(out.size(), size_ - offset));
    std::size_t done = 0;
    while (done < want) {
      const ssize_t r = ::pread(fd_, out.data() + done, want - done, static_cast<off_t>(offset + done));
      if (r < 0 && errno == EINTR) continue;
      if (r <= 0) break;
      done += static_cast<std::size_t>(r);
    }
    return done;
  }

 private:
  int fd_;
  std::uint64_t size_;
  std::shared_ptr<Budget> budget_;
  std::uint64_t charged_;
};

class SliceSource final : public Source {
 public:
  SliceSource(std::shared_ptr<const Source> base, std::uint64_t offset, std::uint64_t size)
      : base_(std::move(base)), offset_(offset), size_(size) {}
  std::uint64_t size() const override { return size_; }
  std::size_t read(std::uint64_t offset, std::span<std::byte> out) const override {
    if (offset >= size_) return 0;
    const std::size_t n = static_cast<std::size_t>(std::min<std::uint64_t>(out.size(), size_ - offset));
    return base_->read(offset_ + offset, out.first(n));
  }
  std::span<const std::byte> view() const override {
    auto v = base_->view();
    if (v.empty()) return {};
    return v.subspan(static_cast<std::size_t>(offset_), static_cast<std::size_t>(size_));
  }

 private:
  std::shared_ptr<const Source> base_;
  std::uint64_t offset_, size_;
};

int temp_file() {
  std::error_code ec;
  std::string dir = std::filesystem::temp_directory_path(ec).string();
  if (ec || dir.empty()) dir = "/tmp";
#ifdef O_TMPFILE
  int fd = ::open(dir.c_str(), O_TMPFILE | O_RDWR | O_EXCL | O_CLOEXEC, 0600);
  if (fd >= 0) return fd;
#endif
  std::string tmpl = dir + "/revkit-container-XXXXXX";
  fd = ::mkstemp(tmpl.data());
  if (fd < 0) throw Error(std::string("cannot make a temporary file: ") + std::strerror(errno));
  ::unlink(tmpl.c_str());
  return fd;
}

void write_all(int fd, const std::byte *p, std::size_t n) {
  while (n) {
    const ssize_t w = ::write(fd, p, n);
    if (w < 0 && errno == EINTR) continue;
    if (w <= 0) throw Error(std::string("cannot write a temporary file: ") + std::strerror(errno));
    p += w;
    n -= static_cast<std::size_t>(w);
  }
}

// One UTF-8 sequence at s[i]: its length, or 0 when it isn't valid
// (overlong, a surrogate, past U+10FFFF, truncated).
std::size_t utf8_length(std::string_view s, std::size_t i, std::uint32_t &cp) {
  const auto b = [&](std::size_t k) { return static_cast<std::uint8_t>(s[k]); };
  const std::uint8_t c = b(i);
  if (c < 0x80) {
    cp = c;
    return 1;
  }
  std::size_t n;
  if ((c & 0xe0) == 0xc0) {
    n = 2;
    cp = c & 0x1f;
  } else if ((c & 0xf0) == 0xe0) {
    n = 3;
    cp = c & 0x0f;
  } else if ((c & 0xf8) == 0xf0) {
    n = 4;
    cp = c & 0x07;
  } else {
    return 0;
  }
  if (i + n > s.size()) return 0;
  for (std::size_t k = 1; k < n; ++k) {
    if ((b(i + k) & 0xc0) != 0x80) return 0;
    cp = (cp << 6) | (b(i + k) & 0x3f);
  }
  if ((n == 2 && cp < 0x80) || (n == 3 && cp < 0x800) || (n == 4 && cp < 0x10000)) return 0;
  if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return 0;
  return n;
}

// Characters that change how the text around them shows (bidirectional
// overrides and isolates): a name could pose as another ("exe.txt").
bool deceptive(std::uint32_t cp) {
  return (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069) || cp == 0x200e || cp == 0x200f ||
         (cp >= 0x80 && cp < 0xa0);
}

constexpr char kHex[] = "0123456789ABCDEF";

}  // namespace

void Budget::charge(std::uint64_t n) {
  const std::uint64_t before = used_.fetch_add(n);
  if (before + n > limit_ || before + n < before) {
    used_.fetch_sub(n);
    throw LimitError("the session holds " + mib(before) + " of decompressed data; " + mib(n) +
                     " more passes its limit of " + mib(limit_) + " (close other files first)");
  }
}

void Context::check_cancelled() const {
  if (cancelled && cancelled()) throw Error("cancelled");
}

std::vector<std::byte> Source::read_exact(std::uint64_t offset, std::uint64_t n, std::string_view what) const {
  if (offset > size() || n > size() - offset)
    throw Error(std::string(what) + " lies outside the data (offset " + std::to_string(offset) + ", " +
                std::to_string(n) + " bytes of " + std::to_string(size()) + ")");
  if (n > (1ull << 31)) throw LimitError(std::string(what) + " is too large to read at once");
  std::vector<std::byte> out(static_cast<std::size_t>(n));
  if (read(offset, out) != n) throw Error(std::string(what) + ": short read");
  return out;
}

std::vector<std::byte> Source::head(std::uint64_t n) const {
  std::vector<std::byte> out(static_cast<std::size_t>(std::min(n, size())));
  out.resize(read(0, out));
  return out;
}

std::shared_ptr<Source> memory_source(std::vector<std::byte> bytes) {
  return std::make_shared<MemorySource>(std::move(bytes), nullptr, 0);
}

std::shared_ptr<Source> file_source(int fd_owned, std::uint64_t size) {
  return std::make_shared<FileSource>(fd_owned, size);
}

std::shared_ptr<Source> open_host_file(const std::string &path) {
  // O_NONBLOCK: a FIFO is refused below instead of blocking the open.
  const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
  if (fd < 0) throw Error("cannot open " + path + ": " + std::strerror(errno));
  struct stat st {};
  if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
    ::close(fd);
    throw Error(path + " is not a regular file");
  }
  return std::make_shared<FileSource>(fd, static_cast<std::uint64_t>(st.st_size));
}

std::shared_ptr<Source> slice(std::shared_ptr<const Source> base, std::uint64_t offset, std::uint64_t size) {
  if (offset > base->size() || size > base->size() - offset)
    throw Error("a member lies outside its container (offset " + std::to_string(offset) + ", size " +
                std::to_string(size) + ", container " + std::to_string(base->size()) + " bytes)");
  return std::make_shared<SliceSource>(std::move(base), offset, size);
}

// ---- Sink --------------------------------------------------------------------------

Sink::Sink(const Context &ctx, std::uint64_t stop_after)
    : ctx_(ctx), stop_after_(stop_after), max_(ctx.limits.max_file_bytes) {}

Sink::~Sink() {
  if (fd_ >= 0) ::close(fd_);
  if (charged_ && ctx_.budget) ctx_.budget->release(charged_);
}

void Sink::append(std::span<const std::byte> data) {
  if (full() || data.empty()) return;
  const std::uint64_t take = std::min<std::uint64_t>(data.size(), stop_after_ - size_);
  if (size_ + take > max_)
    throw LimitError("a file decompresses to more than " + mib(max_) + ", the limit for one file");
  if (ctx_.budget) ctx_.budget->charge(take);
  charged_ += take;
  if (fd_ < 0 && size_ + take > ctx_.limits.memory_threshold) spill();
  if (fd_ >= 0) {
    write_all(fd_, data.data(), static_cast<std::size_t>(take));
  } else {
    mem_.insert(mem_.end(), data.begin(), data.begin() + static_cast<std::ptrdiff_t>(take));
  }
  size_ += take;
  check_ratio();
}

void Sink::consumed(std::uint64_t compressed_total) {
  compressed_ = compressed_total;
  check_ratio();
}

void Sink::check_ratio() const {
  if (size_ > ctx_.limits.ratio_floor && compressed_ > 0 && size_ / compressed_ > ctx_.limits.max_ratio)
    throw LimitError("a file decompresses more than " + std::to_string(ctx_.limits.max_ratio) +
                     " times its compressed size (" + mib(compressed_) + " to over " + mib(size_) +
                     "): refused as a decompression bomb");
}

void Sink::spill() {
  fd_ = temp_file();
  write_all(fd_, mem_.data(), mem_.size());
  std::vector<std::byte>().swap(mem_);
}

std::shared_ptr<Source> Sink::finish() {
  std::shared_ptr<Source> out;
  if (fd_ >= 0) {
    out = std::make_shared<FileSource>(fd_, size_, ctx_.budget, charged_);
    fd_ = -1;
  } else {
    out = std::make_shared<MemorySource>(std::move(mem_), ctx_.budget, charged_);
  }
  charged_ = 0;
  return out;
}

// ---- names -------------------------------------------------------------------------

std::string display_name(std::string_view raw) {
  std::string out;
  out.reserve(raw.size());
  for (std::size_t i = 0; i < raw.size();) {
    std::uint32_t cp = 0;
    const std::size_t n = utf8_length(raw, i, cp);
    if (n == 0 || cp < 0x20 || cp == 0x7f || deceptive(cp)) {
      out += "\xEF\xBF\xBD";
      i += n ? n : 1;
      continue;
    }
    out.append(raw.substr(i, n));
    i += n;
  }
  return out;
}

std::string encode_component(std::string_view raw) {
  std::string out;
  out.reserve(raw.size());
  auto escape = [&](std::uint8_t c) {
    out += '%';
    out += kHex[c >> 4];
    out += kHex[c & 15];
  };
  for (std::size_t i = 0; i < raw.size();) {
    std::uint32_t cp = 0;
    const std::size_t n = utf8_length(raw, i, cp);
    if (n == 0) {
      escape(static_cast<std::uint8_t>(raw[i]));
      ++i;
      continue;
    }
    if (n == 1 && (cp < 0x20 || cp == 0x7f || cp == '%' || cp == '!' || cp == '/')) {
      escape(static_cast<std::uint8_t>(cp));
    } else if (deceptive(cp)) {
      for (std::size_t k = 0; k < n; ++k) escape(static_cast<std::uint8_t>(raw[i + k]));
    } else {
      out.append(raw.substr(i, n));
    }
    i += n;
  }
  return out;
}

std::string decode_component(std::string_view encoded) {
  std::string out;
  out.reserve(encoded.size());
  auto hexval = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  for (std::size_t i = 0; i < encoded.size(); ++i) {
    if (encoded[i] != '%') {
      out += encoded[i];
      continue;
    }
    const int hi = i + 1 < encoded.size() ? hexval(encoded[i + 1]) : -1;
    const int lo = i + 2 < encoded.size() ? hexval(encoded[i + 2]) : -1;
    if (hi < 0 || lo < 0) throw Error("a path has a malformed escape (use %XX)");
    out += static_cast<char>(hi * 16 + lo);
    i += 2;
  }
  return out;
}

std::vector<std::string> split_path(std::string_view encoded) {
  std::vector<std::string> out;
  std::size_t i = 0;
  while (i <= encoded.size()) {
    std::size_t j = encoded.find('/', i);
    if (j == std::string_view::npos) j = encoded.size();
    if (j > i) {
      std::string c = decode_component(encoded.substr(i, j - i));
      if (!c.empty() && c != ".") out.push_back(std::move(c));
    }
    i = j + 1;
  }
  return out;
}

std::string join_path(const std::vector<std::string> &raw_components) {
  if (raw_components.empty()) return "/";
  std::string out;
  for (const std::string &c : raw_components) out += "/" + encode_component(c);
  return out;
}

std::string_view name(Kind k) {
  switch (k) {
    case Kind::file: return "file";
    case Kind::directory: return "directory";
    case Kind::symlink: return "symlink";
    case Kind::char_device: return "char-device";
    case Kind::block_device: return "block-device";
    case Kind::fifo: return "fifo";
    case Kind::socket: return "socket";
    case Kind::hardlink: return "hardlink";
    case Kind::other: return "other";
  }
  return "other";
}

// ---- FileSystem ---------------------------------------------------------------------

std::vector<std::string> FileSystem::components_of(std::uint32_t i) const {
  std::vector<std::string> out;
  for (std::uint32_t guard = 0; i != 0 && guard < 100000; ++guard) {
    out.push_back(entries_.at(i).name);
    i = entries_.at(i).parent;
  }
  std::reverse(out.begin(), out.end());
  return out;
}

std::string FileSystem::path_of(std::uint32_t i) const { return join_path(components_of(i)); }

namespace {

std::optional<std::uint32_t> child_of(const std::vector<Entry> &entries, std::uint32_t dir, const std::string &name) {
  const auto &kids = entries[dir].children;
  auto it = std::lower_bound(kids.begin(), kids.end(), name,
                             [&](std::uint32_t c, const std::string &n) { return entries[c].name < n; });
  if (it == kids.end() || entries[*it].name != name) return std::nullopt;
  return *it;
}

}  // namespace

std::optional<std::uint32_t> FileSystem::find(const std::vector<std::string> &components, bool follow_last,
                                              std::uint32_t max_hops) const {
  if (entries_.empty()) return std::nullopt;
  std::deque<std::string> todo(components.begin(), components.end());
  std::uint32_t cur = 0, hops = 0;
  while (!todo.empty()) {
    std::string c = std::move(todo.front());
    todo.pop_front();
    if (c.empty() || c == ".") continue;
    if (c == "..") {
      cur = entries_[cur].parent;
      continue;
    }
    if (entries_[cur].kind != Kind::directory) return std::nullopt;
    auto next = child_of(entries_, cur, c);
    if (!next) return std::nullopt;
    const Entry &e = entries_[*next];
    const bool link = e.kind == Kind::symlink || e.kind == Kind::hardlink;
    if (link && (follow_last || !todo.empty())) {
      if (++hops > max_hops)
        throw LimitError("more than " + std::to_string(max_hops) + " symbolic links on the way (a loop?)");
      if (todo.size() + 64 > 65536) throw LimitError("a symbolic link expands too far");
      // Its target, then what was left of the path.
      std::vector<std::string> parts;
      std::string_view t = e.link_target;
      std::size_t i = 0;
      while (i <= t.size()) {
        std::size_t j = t.find('/', i);
        if (j == std::string_view::npos) j = t.size();
        if (j > i) parts.emplace_back(t.substr(i, j - i));
        i = j + 1;
      }
      // Hard links name a path from the archive's root; symlinks are
      // relative to their directory unless absolute. Either way the root
      // is the container's.
      if (e.kind == Kind::hardlink || (!t.empty() && t[0] == '/')) cur = 0;
      for (auto it = parts.rbegin(); it != parts.rend(); ++it) todo.push_front(*it);
      if (e.link_target.empty()) return std::nullopt;
      continue;
    }
    cur = *next;
  }
  return cur;
}

std::optional<std::uint32_t> FileSystem::resolve_link(std::uint32_t link, std::uint32_t max_hops) const {
  return find(components_of(link), true, max_hops);
}

std::vector<std::byte> FileSystem::head(std::uint32_t entry, std::uint64_t n, const Context &ctx) const {
  return open(entry, ctx)->head(n);
}

// ---- TreeBuilder ------------------------------------------------------------------

namespace {
std::string key_of(std::uint32_t parent, const std::string &name) {
  std::string k(reinterpret_cast<const char *>(&parent), sizeof parent);
  k += name;
  return k;
}
}  // namespace

struct TreeBuilder::Index {
  std::unordered_map<std::string, std::uint32_t> by_name;
  std::vector<std::uint32_t> depth;
};

TreeBuilder::TreeBuilder(FileSystem &fs, const Limits &limits)
    : fs_(fs), limits_(limits), ix_(std::make_unique<Index>()) {
  fs_.entries_.clear();
  Entry root;
  root.kind = Kind::directory;
  fs_.entries_.push_back(std::move(root));
  ix_->depth.assign(1, 0);
}

TreeBuilder::~TreeBuilder() = default;

std::size_t TreeBuilder::count() const { return fs_.entries_.size(); }

std::uint32_t TreeBuilder::child_named(std::uint32_t parent, const std::string &name) const {
  auto it = ix_->by_name.find(key_of(parent, name));
  return it == ix_->by_name.end() ? UINT32_MAX : it->second;
}

std::uint32_t TreeBuilder::depth_of(std::uint32_t i) const { return ix_->depth.at(i); }

std::uint32_t TreeBuilder::add_child(std::uint32_t parent, Entry e) {
  if (e.name.empty() || e.name == "." || e.name == "..") throw Error("an entry has no usable name");
  if (parent >= fs_.entries_.size() || fs_.entries_[parent].kind != Kind::directory)
    throw Error("an entry's parent is not a directory");
  Index &ix = *ix_;
  if (ix.depth[parent] + 1 > limits_.max_dir_depth)
    throw LimitError("directories nest deeper than " + std::to_string(limits_.max_dir_depth));
  std::uint32_t existing = child_named(parent, e.name);
  if (existing != UINT32_MAX) {
    Entry &old = fs_.entries_[existing];
    if (old.kind == Kind::directory && e.kind == Kind::directory) {
      // The same directory listed again: newer metadata, same children.
      e.children = std::move(old.children);
      e.parent = parent;
      e.renamed = e.renamed || old.renamed;
      old = std::move(e);
      return existing;
    }
    if (old.kind != Kind::directory && e.kind != Kind::directory && !keep_duplicates) {
      // A file listed again (an archive appended to): the later one wins,
      // as extracting it would.
      e.parent = parent;
      old = std::move(e);
      return existing;
    }
    // A file and a directory of one name: keep both, the later renamed.
    const std::string base = e.name;
    for (int n = 2;; ++n) {
      e.name = base + "~" + std::to_string(n);
      if (child_named(parent, e.name) == UINT32_MAX) break;
      if (n > 1000) throw Error("too many entries named " + display_name(base));
    }
    e.renamed = true;
  }
  if (fs_.entries_.size() >= limits_.max_entries)
    throw LimitError("more than " + std::to_string(limits_.max_entries) + " entries in one container");
  e.parent = parent;
  e.children.clear();
  const std::uint32_t idx = static_cast<std::uint32_t>(fs_.entries_.size());
  ix.by_name.emplace(key_of(parent, e.name), idx);
  ix.depth.push_back(ix.depth[parent] + 1);
  fs_.entries_[parent].children.push_back(idx);
  fs_.entries_.push_back(std::move(e));
  return idx;
}

std::uint32_t TreeBuilder::directory(std::string_view path) {
  Entry d;
  d.kind = Kind::directory;
  return add_path(path, std::move(d));
}

std::uint32_t TreeBuilder::add_path(std::string_view path, Entry e) {
  std::vector<std::string> parts;
  bool escaped = false;
  std::size_t i = 0;
  while (i <= path.size()) {
    std::size_t j = path.find('/', i);
    if (j == std::string_view::npos) j = path.size();
    std::string c(path.substr(i, j - i));
    i = j + 1;
    if (c.empty() || c == ".") continue;
    if (c == "..") {
      if (parts.empty())
        escaped = true;
      else
        parts.pop_back();
      continue;
    }
    parts.push_back(std::move(c));
  }
  if (escaped) {
    e.renamed = true;
    if (e.note.empty()) e.note = "stored as " + display_name(path);
  }
  if (parts.empty()) {
    // The root itself ("./" in a tar): keep its metadata.
    if (e.kind == Kind::directory) {
      Entry &root = fs_.entries_[0];
      root.mode = e.mode;
      root.has_mode = e.has_mode;
      root.mtime = e.mtime;
      root.has_mtime = e.has_mtime;
      root.uid = e.uid;
      root.gid = e.gid;
      root.has_owner = e.has_owner;
    }
    return 0;
  }
  std::uint32_t cur = 0;
  for (std::size_t k = 0; k + 1 < parts.size(); ++k) {
    std::uint32_t next = child_named(cur, parts[k]);
    if (next == UINT32_MAX || fs_.entries_[next].kind != Kind::directory) {
      // Missing (archives needn't list directories), or a file of that
      // name: a directory of its own (renamed when it clashes).
      Entry d;
      d.kind = Kind::directory;
      d.name = parts[k];
      next = add_child(cur, std::move(d));
    }
    cur = next;
  }
  e.name = parts.back();
  return add_child(cur, std::move(e));
}

void TreeBuilder::finish() {
  auto &entries = fs_.entries_;
  for (Entry &e : entries)
    std::sort(e.children.begin(), e.children.end(),
              [&](std::uint32_t a, std::uint32_t b) { return entries[a].name < entries[b].name; });
  ix_->by_name.clear();
}

}  // namespace revkit::container
