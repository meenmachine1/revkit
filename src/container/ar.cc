// ar: the common format of static libraries and Debian packages (.a, .deb,
// .ipk), with GNU long names ("//" and "/<offset>") and BSD ones
// ("#1/<length>"). The symbol tables ("/", "/SYM64/", "__.SYMDEF") are
// listed as such, not as members.
#include "formats.hh"

#include <charconv>

namespace revkit::container::detail {
namespace {

std::uint64_t decimal(std::string_view s, const char *what) {
  while (!s.empty() && s.back() == ' ') s.remove_suffix(1);
  while (!s.empty() && s.front() == ' ') s.remove_prefix(1);
  if (s.empty()) return 0;
  std::uint64_t v = 0;
  auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
  if (ec != std::errc() || p != s.data() + s.size()) throw Error(std::string("a malformed ar ") + what);
  return v;
}

std::uint64_t octal(std::string_view s) {
  while (!s.empty() && s.back() == ' ') s.remove_suffix(1);
  std::uint64_t v = 0;
  for (char c : s) {
    if (c < '0' || c > '7') return 0;
    v = v * 8 + static_cast<std::uint64_t>(c - '0');
  }
  return v;
}

class Ar final : public SliceFileSystem {
 public:
  using SliceFileSystem::SliceFileSystem;

  void parse(const Context &ctx) {
    format_ = "ar";
    TreeBuilder tree(*this, ctx.limits);
    tree.keep_duplicates = true;
    const std::uint64_t size = src_->size();
    std::uint64_t off = 8, members = 0;
    std::string longnames;
    bool symbols = false;
    while (off + 60 <= size) {
      ctx.check_cancelled();
      const auto hb = src_->read_exact(off, 60, "an ar header");
      const std::string h(reinterpret_cast<const char *>(hb.data()), 60);
      if (h.compare(58, 2, "`\n") != 0) {
        warn("stopped at offset " + std::to_string(off) + ": not an ar header");
        break;
      }
      std::string name = h.substr(0, 16);
      const std::uint64_t msize = decimal(std::string_view(h).substr(48, 10), "size");
      std::uint64_t data = off + 60;
      std::uint64_t len = msize;
      if (data > size || msize > size - data) {
        warn("the last member is truncated");
        break;
      }
      const std::uint64_t next = data + msize + (msize & 1);
      while (!name.empty() && name.back() == ' ') name.pop_back();
      if (name == "/" || name == "/SYM64/" || name == "__.SYMDEF" || name == "__.SYMDEF SORTED") {
        symbols = true;
        off = next;
        continue;
      }
      if (name == "//") {
        if (msize > (16u << 20)) throw LimitError("an ar long-name table over 16 MiB");
        auto t = src_->read_exact(data, msize, "the ar long-name table");
        longnames.assign(reinterpret_cast<const char *>(t.data()), t.size());
        off = next;
        continue;
      }
      if (name.size() > 1 && name[0] == '/' && name[1] >= '0' && name[1] <= '9') {
        // GNU: an offset into the long-name table, "name/\n" there.
        const std::uint64_t at = decimal(std::string_view(name).substr(1), "long name");
        if (at >= longnames.size()) throw Error("an ar long name outside its table");
        std::size_t end = longnames.find('\n', static_cast<std::size_t>(at));
        if (end == std::string::npos) end = longnames.size();
        name = longnames.substr(static_cast<std::size_t>(at), end - static_cast<std::size_t>(at));
        if (!name.empty() && name.back() == '/') name.pop_back();
      } else if (name.rfind("#1/", 0) == 0) {
        // BSD: the name is the first <n> bytes of the data.
        const std::uint64_t n = decimal(std::string_view(name).substr(3), "BSD name length");
        if (n > msize || n > 4096) throw Error("an ar BSD name longer than its member");
        auto nb = src_->read_exact(data, n, "an ar BSD name");
        name.assign(reinterpret_cast<const char *>(nb.data()), n);
        name.resize(strnlen(name.c_str(), name.size()));
        data += n;
        len -= n;
      } else if (!name.empty() && name.back() == '/') {
        name.pop_back();  // GNU short names end in '/'
      }
      if (name.empty()) name = "member" + std::to_string(members);
      Entry e;
      e.kind = Kind::file;
      e.size = len;
      e.stored_size = len;
      e.loc0 = data;
      e.loc1 = len;
      e.mtime = static_cast<std::int64_t>(decimal(std::string_view(h).substr(16, 12), "time"));
      e.has_mtime = true;
      e.uid = static_cast<std::uint32_t>(decimal(std::string_view(h).substr(28, 6), "uid"));
      e.gid = static_cast<std::uint32_t>(decimal(std::string_view(h).substr(34, 6), "gid"));
      e.has_owner = true;
      e.mode = static_cast<std::uint32_t>(octal(std::string_view(h).substr(40, 8)) & 07777);
      e.has_mode = true;
      // Members are names, not paths: a '/' in one stays in the name.
      std::string flat = name;
      for (char &c : flat)
        if (c == '/') c = '_';
      if (flat == "." || flat == "..") flat = "_" + flat;
      e.name = flat;
      tree.add_child(0, std::move(e));
      ++members;
      off = next;
    }
    tree.finish();
    description_ = "ar archive, " + plural(members, "member", "members") + (symbols ? " and a symbol table" : "");
  }
};

}  // namespace

std::shared_ptr<FileSystem> open_ar(std::shared_ptr<const Source> src, std::string_view, const Context &ctx) {
  auto fs = std::make_shared<Ar>(std::move(src));
  fs->parse(ctx);
  return fs;
}

}  // namespace revkit::container::detail
