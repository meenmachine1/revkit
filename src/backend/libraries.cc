#include "libraries.h"

#include "open_beneath.h"

#include <algorithm>
#include <cerrno>
#include <array>
#include <cctype>
#include <fstream>
#include <set>
#include <deque>
#include <system_error>

#include <fcntl.h>
#include <fnmatch.h>
#include <sys/stat.h>
#include <unistd.h>

namespace revkit::backend::libs {

namespace fs = std::filesystem;

std::string StripVersion(std::string_view name) {
  return std::string(name.substr(0, name.find('@')));
}

static std::string Lower(std::string_view s) {
  std::string out(s);
  for (char &c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return out;
}

bool SameLibrary(std::string_view a, std::string_view b, bool pe) {
  return pe ? Lower(a) == Lower(b) : a == b;
}

std::string LibraryLeaf(std::string_view name) {
  const std::size_t slash = name.rfind('/');
  return std::string(slash == std::string_view::npos ? name : name.substr(slash + 1));
}

std::map<std::string, std::uint64_t> Exports(const loader::Image &img) {
  std::map<std::string, std::uint64_t> out;
  if (img.format == loader::Format::pe || (img.format == loader::Format::macho && !img.exports.empty())) {
    for (const loader::Export &e : img.exports)
      if (!e.name.empty() && e.forwarder.empty() && e.address != 0) out.emplace(e.name, e.address);
    return out;
  }
  const bool dynsym = std::any_of(img.symbols.begin(), img.symbols.end(),
                                  [](const loader::Symbol &s) { return s.source == loader::SymbolSource::dynsym; });
  for (const loader::Symbol &s : img.symbols) {
    if (!s.defined || s.value == 0 || s.name.empty()) continue;
    if (dynsym && s.source != loader::SymbolSource::dynsym) continue;
    if (s.bind != loader::SymbolBind::global && s.bind != loader::SymbolBind::weak) continue;
    if (s.type != loader::SymbolType::func && s.type != loader::SymbolType::ifunc && s.type != loader::SymbolType::object)
      continue;
    std::string name = StripVersion(s.name);
    // A global definition wins over a weak one of the same name.
    auto [it, fresh] = out.emplace(name, s.value);
    if (!fresh && s.bind == loader::SymbolBind::global) it->second = s.value;
  }
  return out;
}

// A header's arch, reading through `read(offset, n)`.
template <class Read>
static std::optional<FileArch> PeekWith(Read &&read) {
  const std::vector<unsigned char> h = read(0, 64);
  if (h.size() < 20) return std::nullopt;
  FileArch a;
  if (h[0] == 0x7f && h[1] == 'E' && h[2] == 'L' && h[3] == 'F') {
    a.format = loader::Format::elf;
    a.bits = h[4] == 2 ? 64 : 32;
    a.endian = h[5] == 2 ? loader::Endian::big : loader::Endian::little;
    a.machine = a.endian == loader::Endian::little ? (h[18] | (h[19] << 8)) : ((h[18] << 8) | h[19]);
    return a;
  }
  {
    // Mach-O: thin, or universal (each slice's CPU from the fat header).
    const std::uint32_t le = h[0] | (h[1] << 8) | (h[2] << 16) | (static_cast<std::uint32_t>(h[3]) << 24);
    const std::uint32_t be = (static_cast<std::uint32_t>(h[0]) << 24) | (h[1] << 16) | (h[2] << 8) | h[3];
    auto rd = [&](const std::vector<unsigned char> &b, std::size_t at, bool big) -> std::uint32_t {
      return big ? (static_cast<std::uint32_t>(b[at]) << 24) | (b[at + 1] << 16) | (b[at + 2] << 8) | b[at + 3]
                 : b[at] | (b[at + 1] << 8) | (b[at + 2] << 16) | (static_cast<std::uint32_t>(b[at + 3]) << 24);
    };
    if (le == 0xfeedface || le == 0xfeedfacf || le == 0xcefaedfe || le == 0xcffaedfe) {
      a.format = loader::Format::macho;
      a.bits = le == 0xfeedfacf || le == 0xcffaedfe ? 64 : 32;
      a.endian = le == 0xfeedface || le == 0xfeedfacf ? loader::Endian::little : loader::Endian::big;
      a.machine = rd(h, 4, a.endian == loader::Endian::big);
      return a;
    }
    if (be == 0xcafebabe || be == 0xcafebabf) {
      const std::uint32_t n = rd(h, 4, true);
      if (n == 0 || n > 64) return std::nullopt;  // a Java class file
      const std::size_t entry = be == 0xcafebabf ? 32 : 20;
      const std::vector<unsigned char> f = read(0, 8 + n * entry);
      if (f.size() < 8 + n * entry) return std::nullopt;
      a.format = loader::Format::macho;
      for (std::uint32_t i = 0; i < n; ++i) a.slices.emplace_back(rd(f, 8 + i * entry, true), rd(f, 12 + i * entry, true));
      a.machine = a.slices[0].first;
      a.bits = (a.machine & 0x01000000) != 0 ? 64 : 32;
      return a;
    }
  }
  if (h[0] == 'M' && h[1] == 'Z' && h.size() >= 0x40) {
    const std::uint32_t pe = h[0x3c] | (h[0x3d] << 8) | (h[0x3e] << 16) | (static_cast<std::uint32_t>(h[0x3f]) << 24);
    if (pe > (1u << 20)) return std::nullopt;
    const std::vector<unsigned char> p = read(pe, 26);
    if (p.size() < 26 || p[0] != 'P' || p[1] != 'E' || p[2] != 0 || p[3] != 0) return std::nullopt;
    a.format = loader::Format::pe;
    a.machine = p[4] | (p[5] << 8);
    const unsigned magic = p[24] | (p[25] << 8);
    a.bits = magic == 0x20b ? 64 : 32;
    return a;
  }
  return std::nullopt;
}

std::optional<FileArch> PeekArch(const fs::path &file) {
  std::ifstream in(file, std::ios::binary);
  if (!in) return std::nullopt;
  return PeekWith([&](std::uint64_t offset, std::size_t n) {
    std::vector<unsigned char> out(n);
    in.clear();
    in.seekg(static_cast<std::streamoff>(offset));
    in.read(reinterpret_cast<char *>(out.data()), static_cast<std::streamsize>(n));
    out.resize(static_cast<std::size_t>(std::max<std::streamsize>(in.gcount(), 0)));
    return out;
  });
}

std::optional<FileArch> PeekArchIn(LibraryRoot &root, const std::string &key) {
  return PeekWith([&](std::uint64_t offset, std::size_t n) { return root.read(key, offset, n); });
}

bool Compatible(const FileArch &a, const loader::Image &img) {
  if (a.format == loader::Format::macho && !a.slices.empty() && img.format == loader::Format::macho)
    return std::any_of(a.slices.begin(), a.slices.end(), [&](const auto &s) { return s.first == img.machine; });
  return a.format == img.format && a.bits == img.bits && a.machine == img.machine &&
         (a.format == loader::Format::pe || a.endian == img.endian);
}

std::string MachoSliceFor(const FileArch &a, const loader::Image &img) {
  if (a.slices.empty() || !img.macho) return {};
  for (bool exact : {true, false})
    for (std::size_t i = 0; i < a.slices.size(); ++i)
      if (a.slices[i].first == img.machine &&
          (!exact || (a.slices[i].second & 0x00ffffff) == (img.macho->cpusubtype & 0x00ffffff)))
        return "#" + std::to_string(i);
  return {};
}

// The Debian/Ubuntu multiarch directory name for an ELF machine.
static std::string Triplet(const loader::Image &img) {
  switch (img.machine) {
    case 62: return "x86_64-linux-gnu";
    case 3: return "i386-linux-gnu";
    case 183: return "aarch64-linux-gnu";
    case 40: return "arm-linux-gnueabihf";
    case 243: return img.bits == 64 ? "riscv64-linux-gnu" : "";
    case 8: return img.endian == loader::Endian::big ? "mips-linux-gnu" : "mipsel-linux-gnu";
    case 21: return "powerpc64le-linux-gnu";
    default: return "";
  }
}

// The dynamic linker's default directories for an ELF of this machine.
static std::vector<std::string> StandardDirs(const loader::Image &img) {
  std::vector<std::string> out;
  const std::string t = Triplet(img);
  for (const std::string d : {"/lib", "/usr/lib"}) {
    if (!t.empty()) out.push_back(d + "/" + t);
    out.push_back(d + (img.bits == 64 ? "64" : "32"));
    out.push_back(d);
  }
  out.push_back("/usr/local/lib");
  return out;
}

std::vector<fs::path> SearchDirs(const std::vector<std::string> &user, const std::string &source_path,
                                 const loader::Image &img, bool host) {
  std::vector<fs::path> out;
  std::set<std::string> seen;
  auto add = [&](const fs::path &d) {
    std::error_code ec;
    if (!d.is_absolute() || !fs::is_directory(d, ec)) return;
    const std::string key = d.lexically_normal().string();
    if (seen.insert(key).second) out.push_back(d.lexically_normal());
  };
  for (const std::string &u : user) add(fs::path(u));
  if (!source_path.empty()) {
    const fs::path origin = fs::path(source_path).parent_path();
    add(origin);
    if (img.format == loader::Format::macho) {
      // LC_RPATH: @loader_path and @executable_path are the file's directory.
      for (std::string r : img.runpath) {
        for (std::string_view o : {"@loader_path", "@executable_path"})
          if (r.starts_with(o)) r = origin.string() + r.substr(o.size());
        if (!r.empty() && r.front() == '/') add(fs::path(r));
      }
    } else {
    for (std::string r : img.runpath) {
      for (std::string_view o : {"${ORIGIN}", "$ORIGIN"})
        for (std::size_t at; (at = r.find(o)) != std::string::npos;) r.replace(at, o.size(), origin.string());
      add(fs::path(r));
    }
    }
  }
  if (host && img.format == loader::Format::elf)
    for (const std::string &d : StandardDirs(img)) add(fs::path(d));
  return out;
}

std::optional<fs::path> FindLibrary(const std::string &needed, const std::vector<fs::path> &dirs, const loader::Image &img) {
  const std::string name = img.format == loader::Format::macho ? LibraryLeaf(needed) : needed;
  if (name.empty() || name.find('/') != std::string::npos || name == "." || name == "..") return std::nullopt;
  const bool pe = img.format == loader::Format::pe;
  auto fits = [&](const fs::path &f) {
    std::error_code ec;
    if (!fs::is_regular_file(f, ec)) return false;
    auto a = PeekArch(f);
    return a && Compatible(*a, img);
  };
  for (const fs::path &d : dirs) {
    if (fits(d / name)) return d / name;
    if (!pe) continue;
    // Windows names are case-insensitive: KERNEL32.dll is kernel32.dll.
    std::error_code ec;
    for (fs::directory_iterator it(d, ec), end; !ec && it != end; it.increment(ec))
      if (SameLibrary(it->path().filename().string(), name, true) && fits(it->path())) return it->path();
  }
  return std::nullopt;
}

// --- Roots ---------------------------------------------------------------

static std::vector<std::string> SplitPath(std::string_view p) {
  std::vector<std::string> out;
  std::size_t at = 0;
  while (at <= p.size()) {
    const std::size_t slash = p.find('/', at);
    const std::size_t end = slash == std::string_view::npos ? p.size() : slash;
    if (end > at) out.emplace_back(p.substr(at, end - at));
    if (slash == std::string_view::npos) break;
    at = slash + 1;
  }
  return out;
}

namespace {

class HostRootImpl final : public LibraryRoot {
 public:
  explicit HostRootImpl(fs::path root) : root_(std::move(root)) {}

  std::optional<std::string> file(const std::string &path) override {
    auto p = Resolve(path);
    struct stat st {};
    if (!p || ::lstat(p->c_str(), &st) != 0 || !S_ISREG(st.st_mode)) return std::nullopt;
    return p->string();
  }
  std::vector<std::string> names(const std::string &dir) override {
    std::vector<std::string> out;
    auto p = Resolve(dir);
    struct stat st {};
    if (!p || ::lstat(p->c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) return out;
    std::error_code ec;
    for (fs::directory_iterator it(*p, ec), end; !ec && it != end && out.size() < kMaxNames; it.increment(ec))
      out.push_back(it->path().filename().string());
    return out;
  }
  std::vector<unsigned char> read(const std::string &key, std::uint64_t offset, std::size_t n) override {
    std::vector<unsigned char> out;
    const int fd = Open(key);
    if (fd < 0) return out;
    out.resize(n);
    const ssize_t got = ::pread(fd, out.data(), n, static_cast<off_t>(offset));
    ::close(fd);
    out.resize(got > 0 ? static_cast<std::size_t>(got) : 0);
    return out;
  }
  std::shared_ptr<loader::Bytes> read_all(const std::string &key, std::uint64_t max) override {
    const int fd = Open(key);
    if (fd < 0) return nullptr;
    struct stat st {};
    std::shared_ptr<loader::Bytes> out;
    if (::fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && static_cast<std::uint64_t>(st.st_size) <= max) {
      out = std::make_shared<loader::Bytes>(static_cast<std::size_t>(st.st_size));
      std::size_t done = 0;
      while (done < out->size()) {
        const ssize_t got = ::pread(fd, out->data() + done, out->size() - done, static_cast<off_t>(done));
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) break;
        done += static_cast<std::size_t>(got);
      }
      if (done != out->size()) out.reset();
    }
    ::close(fd);
    return out;
  }
  std::string origin(const std::string &key) override {
    const fs::path rel = fs::path(key).lexically_relative(root_);
    return "/" + rel.parent_path().string();
  }

 private:
  static constexpr std::size_t kMaxNames = 65536;
  // A path inside the root on the host, every component checked with
  // lstat and links followed inside the root (at most 40).
  std::optional<fs::path> Resolve(const std::string &path) const {
    if (path.size() > 4096) return std::nullopt;
    std::deque<std::string> todo;
    for (std::string &c : SplitPath(path)) todo.push_back(std::move(c));
    std::vector<std::string> cur;
    int hops = 0;
    while (!todo.empty()) {
      std::string c = std::move(todo.front());
      todo.pop_front();
      if (c == ".") continue;
      if (c == "..") {
        if (!cur.empty()) cur.pop_back();
        continue;
      }
      fs::path p = root_;
      for (const std::string &x : cur) p /= x;
      p /= c;
      struct stat st {};
      if (::lstat(p.c_str(), &st) != 0) return std::nullopt;
      if (S_ISLNK(st.st_mode)) {
        if (++hops > 40) return std::nullopt;
        char buf[4096];
        const ssize_t n = ::readlink(p.c_str(), buf, sizeof buf);
        if (n <= 0 || static_cast<std::size_t>(n) >= sizeof buf) return std::nullopt;
        const std::string target(buf, static_cast<std::size_t>(n));
        if (target.front() == '/') cur.clear();
        std::vector<std::string> tc = SplitPath(target);
        todo.insert(todo.begin(), tc.begin(), tc.end());
        continue;
      }
      if (!todo.empty() && !S_ISDIR(st.st_mode)) return std::nullopt;
      cur.push_back(std::move(c));
    }
    fs::path p = root_;
    for (const std::string &x : cur) p /= x;
    return p;
  }
  // A key (a path Resolve made) opened from the root down without
  // following a link: one swapped in since Resolve checked it (by a local
  // user who can write under the root) is refused, not followed out.
  int Open(const std::string &key) const {
    const fs::path rel = fs::path(key).lexically_relative(root_);
    if (rel.empty() || *rel.begin() == "..") return -1;
    return OpenBeneath(root_, rel, O_RDONLY);
  }
  fs::path root_;
};

}  // namespace

std::shared_ptr<LibraryRoot> HostRoot(const fs::path &root) { return std::make_shared<HostRootImpl>(root); }

static bool AtOrBelow(const fs::path &p, const fs::path &limit) {
  const fs::path rel = p.lexically_relative(limit);
  return !rel.empty() && *rel.begin() != "..";
}

std::optional<fs::path> FindRootFileSystem(const fs::path &file, const fs::path &limit) {
  auto dir_like = [](const fs::path &p) {
    std::error_code ec;
    const fs::file_status st = fs::symlink_status(p, ec);
    return !ec && (fs::is_directory(st) || fs::is_symlink(st));
  };
  for (fs::path dir = file.parent_path(); !dir.empty() && dir != dir.root_path() && AtOrBelow(dir, limit);
       dir = dir.parent_path()) {
    const std::string name = dir.filename().string();
    if (name == "usr" || name == "local") continue;
    const bool lib = dir_like(dir / "lib") || dir_like(dir / "usr" / "lib");
    const bool rest = dir_like(dir / "bin") || dir_like(dir / "sbin") || dir_like(dir / "usr" / "bin") ||
                      dir_like(dir / "etc");
    if (lib && rest) return dir;
  }
  return std::nullopt;
}

// The directories an ld.so.conf in the root names; `depth` 0 follows its
// includes (globs in their last component), once.
static void LdSoConf(LibraryRoot &root, const std::string &file, int depth, std::vector<std::string> &out) {
  auto key = root.file(file);
  if (!key) return;
  const std::vector<unsigned char> bytes = root.read(*key, 0, 64 << 10);
  const std::string text(bytes.begin(), bytes.end());
  std::size_t at = 0;
  while (at < text.size()) {
    std::size_t nl = text.find('\n', at);
    if (nl == std::string::npos) nl = text.size();
    std::string line = text.substr(at, nl - at);
    at = nl + 1;
    if (auto hash = line.find('#'); hash != std::string::npos) line.resize(hash);
    auto blank = [](char c) { return c == ' ' || c == '\t' || c == '\r' || c == ':' || c == ','; };
    std::vector<std::string> words;
    for (std::size_t i = 0; i < line.size();) {
      while (i < line.size() && blank(line[i])) ++i;
      std::size_t j = i;
      while (j < line.size() && !blank(line[j])) ++j;
      if (j > i) words.push_back(line.substr(i, j - i));
      i = j;
    }
    if (words.empty()) continue;
    if (words[0] == "include") {
      if (depth > 0) continue;
      for (std::size_t w = 1; w < words.size(); ++w) {
        std::string pattern = words[w];
        if (pattern.front() != '/') pattern = "/etc/" + pattern;
        const std::size_t slash = pattern.rfind('/');
        const std::string dir = pattern.substr(0, slash), leaf = pattern.substr(slash + 1);
        std::vector<std::string> names = root.names(dir.empty() ? "/" : dir);
        std::sort(names.begin(), names.end());
        std::size_t taken = 0;
        for (const std::string &n : names)
          if (::fnmatch(leaf.c_str(), n.c_str(), 0) == 0 && ++taken <= 64) LdSoConf(root, dir + "/" + n, depth + 1, out);
      }
      continue;
    }
    if (words[0] == "hwcap") continue;
    for (const std::string &w : words)
      if (w.front() == '/' && out.size() < 256) out.push_back(w);
  }
}

std::vector<std::string> RootSearchDirs(LibraryRoot &root, const std::vector<std::string> &user,
                                        const std::string &origin, const loader::Image &img) {
  std::vector<std::string> out;
  std::set<std::string> seen;
  auto add = [&](const std::string &d) {
    if (d.empty() || d.front() != '/') return;
    std::string key = fs::path(d).lexically_normal().string();
    while (key.size() > 1 && key.back() == '/') key.pop_back();
    if (seen.insert(key).second) out.push_back(key);
  };
  for (const std::string &u : user) add(u);
  add(origin);
  if (img.format == loader::Format::macho) {
    for (std::string r : img.runpath) {
      for (std::string_view o : {"@loader_path", "@executable_path"})
        if (r.starts_with(o)) {
          if (origin.empty()) r.clear();
          else r = origin + r.substr(o.size());
        }
      add(r);
    }
    return out;
  }
  if (img.format != loader::Format::elf) return out;
  for (std::string r : img.runpath) {
    if (origin.empty() && r.find("ORIGIN") != std::string::npos) continue;
    for (std::string_view o : {"${ORIGIN}", "$ORIGIN"})
      for (std::size_t at; (at = r.find(o)) != std::string::npos;) r.replace(at, o.size(), origin);
    add(r);
  }
  std::vector<std::string> conf;
  LdSoConf(root, "/etc/ld.so.conf", 0, conf);
  for (const std::string &d : conf) add(d);
  for (const std::string &d : StandardDirs(img)) add(d);
  return out;
}

std::optional<std::string> FindLibraryIn(LibraryRoot &root, const std::string &needed, const std::vector<std::string> &dirs,
                                         const loader::Image &img) {
  if (img.format == loader::Format::macho && needed.starts_with("/"))
    if (auto key = root.file(needed)) {
      auto a = PeekArchIn(root, *key);
      if (a && Compatible(*a, img)) return key;
    }
  const std::string name = img.format == loader::Format::macho ? LibraryLeaf(needed) : needed;
  if (name.empty() || name.find('/') != std::string::npos || name == "." || name == "..") return std::nullopt;
  const bool pe = img.format == loader::Format::pe;
  auto fits = [&](const std::string &key) {
    auto a = PeekArchIn(root, key);
    return a && Compatible(*a, img);
  };
  for (const std::string &d : dirs) {
    const std::string base = d == "/" ? std::string() : d;
    if (auto key = root.file(base + "/" + name); key && fits(*key)) return key;
    if (!pe) continue;
    for (const std::string &n : root.names(d))
      if (SameLibrary(n, name, true))
        if (auto key = root.file(base + "/" + n); key && fits(*key)) return key;
  }
  return std::nullopt;
}

}  // namespace revkit::backend::libs
