// PyInstaller executables: the CArchive ("PKG") the bootloader carries, and
// the PYZ archive of the program's modules inside it. Implemented from
// PyInstaller's documented archive format (doc/advanced-topics.rst, "The
// CArchive" and "The ZlibArchive"; the layout cross-checked against
// PyInstaller/archive/writers.py of 2.0 to 6.22; PyInstaller is
// GPL-2.0-or-later with the bootloader exception: the format only, no code).
//
// The CArchive ends in a cookie (88 bytes, big-endian; 24 in 2.0):
//   "MEI\014\013\012\013\016", u32 package length (cookie included),
//   u32 TOC offset and u32 TOC length (from the package's start), u32 the
//   Python version (major * 100 + minor; major * 10 + minor before 4.6),
//   char[64] the Python library's name.
// On Linux (3.6 and later) the package is the ELF section "pydata", so the
// cookie is at its end; elsewhere it is appended, the cookie at or near the
// end of the file. TOC entries (18 bytes, then the name, padded to 16):
//   u32 entry length, u32 offset, u32 stored length, u32 length, u8 zlib,
//   char type: s script, m module, M package (bare marshalled code from 5.3,
//   a whole .pyc before), z PYZ, b binary, x data, Z zip, l splash, n link
//   (data: the target), o runtime option and d dependency (no data).
// Scripts and modules are bare marshalled code objects: extraction writes
// a .pyc header in front, with the PYZ's magic number (else the release's
// of the cookie's version), so each comes out a valid .pyc.
//
// The PYZ: "PYZ\0", the pyc magic, u32 BE TOC offset; the TOC is a
// marshalled list of (name, (typecode, offset, length)) (a dict of
// name: (ispkg, offset, length) in 2.x), typecodes 0 module, 1 package, 2
// data, 3 namespace package; each entry zlib(marshal(code)), or encrypted
// (before 6.0, with --key: 16 bytes of IV then AES; listed, not read).
#include "pyinstaller.hh"

#include "bytecode.hh"
#include "exe.hh"
#include "formats.hh"
#include "marshal.hh"

#include <algorithm>
#include <map>

namespace revkit::container::detail {

namespace {

constexpr std::string_view kCookieMagic("MEI\014\013\012\013\016", 8);
constexpr std::uint64_t kTail = 1ull << 20;  // where an appended cookie is looked for

struct Cookie {
  std::uint64_t pkg = 0;  // the package's start in the file
  std::uint64_t length = 0, toc = 0, toc_length = 0;
  PyVersion py;
  std::string libname;
  bool old = false;  // the 24-byte cookie of 2.0
};

PyVersion decode_pyvers(std::uint32_t v) {
  if (v >= 100) return {static_cast<int>(v / 100), static_cast<int>(v % 100)};
  return {static_cast<int>(v / 10), static_cast<int>(v % 10)};
}

// A cookie at `at` (the magic's offset), checked against the file.
std::optional<Cookie> cookie_at(const Source &src, std::uint64_t at) {
  for (bool old : {false, true}) {
    const std::uint64_t size = old ? 24 : 88;
    if (at + size > src.size()) continue;
    const auto c = src.read_exact(at, size, "the PyInstaller cookie");
    if (std::memcmp(c.data(), kCookieMagic.data(), 8) != 0) return std::nullopt;
    Cookie k;
    k.old = old;
    k.length = be32(c.data() + 8);
    k.toc = be32(c.data() + 12);
    k.toc_length = be32(c.data() + 16);
    const std::uint32_t pyvers = be32(c.data() + 20);
    k.py = decode_pyvers(pyvers);
    const std::uint64_t end = at + size;
    if (k.length < size || k.length > end) continue;
    k.pkg = end - k.length;
    if (k.toc > k.length || k.toc_length > k.length - k.toc || k.toc_length > (64u << 20)) continue;
    if (k.py.major < 2 || k.py.major > 3) continue;
    if (!old) {
      const char *n = reinterpret_cast<const char *>(c.data() + 24);
      k.libname = std::string(n, strnlen(n, 64));
    }
    return k;
  }
  return std::nullopt;
}

std::optional<Cookie> find_cookie(const Source &src) {
  try {
    if (auto s = elf_section(src, "pydata"); s && s->size >= 24) {
      for (std::uint64_t size : {88ull, 24ull})
        if (s->size >= size)
          if (auto c = cookie_at(src, s->offset + s->size - size)) return c;
    }
    // Appended: the last cookie in the file's last MiB (a code signature
    // or padding may follow it).
    const std::uint64_t n = std::min(src.size(), kTail);
    const auto t = src.read_exact(src.size() - n, n, "the end of the file");
    for (std::size_t i = t.size() >= 8 ? t.size() - 8 + 1 : 0; i-- > 0;) {
      if (static_cast<char>(t[i]) != 'M' || std::memcmp(t.data() + i, kCookieMagic.data(), 8) != 0) continue;
      if (auto c = cookie_at(src, src.size() - n + i)) return c;
    }
  } catch (const Error &) {
  }
  return std::nullopt;
}

std::string pyc_name(std::string name) { return name + ".pyc"; }

class CArchive final : public PycFileSystem {
 public:
  using PycFileSystem::PycFileSystem;

  void parse(const Context &ctx) {
    format_ = "pyinstaller";
    auto c = find_cookie(*src_);
    if (!c) throw Error("no PyInstaller archive (no cookie)");
    const auto toc = src_->read_exact(c->pkg + c->toc, c->toc_length, "the PyInstaller table of contents");
    TreeBuilder tree(*this, ctx.limits);
    struct Pending {
      std::uint32_t entry;
      bool always;  // a script: never has a header of its own
    };
    std::vector<Pending> code;
    std::optional<std::uint16_t> pyz_magic;
    std::uint64_t files = 0, options = 0, deps = 0;
    std::size_t p = 0;
    while (p + 18 <= toc.size()) {
      ctx.check_cancelled();
      const std::uint32_t elen = be32(toc.data() + p);
      if (elen < 18 || elen > toc.size() - p) {
        warn("the table of contents ends in a malformed entry");
        break;
      }
      const std::uint32_t off = be32(toc.data() + p + 4), len = be32(toc.data() + p + 8),
                          ulen = be32(toc.data() + p + 12);
      const std::uint8_t zlib = static_cast<std::uint8_t>(toc[p + 16]);
      const char type = static_cast<char>(toc[p + 17]);
      const char *nm = reinterpret_cast<const char *>(toc.data() + p + 18);
      std::string name(nm, strnlen(nm, elen - 18));
      p += elen;
      if (++files > ctx.limits.max_entries) throw LimitError("the PyInstaller archive lists too many entries");
      if (type == 'o') {
        ++options;
        continue;
      }
      if (type == 'd') {
        ++deps;
        continue;
      }
      std::replace(name.begin(), name.end(), '\\', '/');
      Entry e;
      e.kind = Kind::file;
      e.size = ulen;
      e.stored_size = len;
      if (off > c->length || len > c->length - off) {
        e.loc2 = UINT64_MAX;
        e.note = "its data lies outside the archive";
      } else {
        e.loc0 = c->pkg + off;
        e.loc1 = len;
        e.loc2 = zlib == 1 ? 1 + static_cast<std::uint64_t>(Codec::zlib) : 0;
      }
      switch (type) {
        case 's':
        case 'm':
        case 'M': {
          if (type == 'M') name += "/__init__";
          const std::uint32_t i = tree.add_path(pyc_name(name), e);
          code.push_back({i, type == 's'});
          break;
        }
        case 'n': {
          // A symlink (6.0): the data is its target and a NUL.
          if (e.loc2 == UINT64_MAX || len > 4096) {
            tree.add_path(name, e);
            break;
          }
          Entry l = e;
          l.kind = Kind::symlink;
          auto t = text_of(e, ctx);
          l.link_target = t.substr(0, strnlen(t.c_str(), t.size()));
          l.size = l.link_target.size();
          tree.add_path(name, l);
          break;
        }
        case 'z': {
          e.note = "the PYZ archive of the program's modules";
          tree.add_path(name, e);
          if (!pyz_magic && e.loc2 != UINT64_MAX) {
            try {
              const auto h = head_entry(e, 8, ctx);
              if (h.size() >= 8 && std::memcmp(h.data(), "PYZ\0", 4) == 0 && le16(h.data() + 6) == 0x0a0d)
                pyz_magic = le16(h.data() + 4);
            } catch (const Error &) {
            }
          }
          break;
        }
        default:
          if (type == 'l') e.note = "splash screen resources";
          tree.add_path(name, e);
      }
    }
    tree.finish();
    // The magic the scripts' .pyc headers get: the PYZ's, which is the
    // interpreter's own, else the release's of the cookie's version.
    std::uint16_t magic = pyz_magic.value_or(pyc_release_magic(c->py));
    if (!magic) warn("no pyc magic number is known for Python " + c->py.str() + ": scripts are left bare");
    for (const Pending &pc : code) {
      Entry &e = entries_[pc.entry];
      if (e.loc2 == UINT64_MAX || !magic) continue;
      // Modules before 5.3 kept their .pyc header: those are left as they are.
      bool bare = pc.always;
      if (!bare) {
        try {
          const auto h = head_entry(e, 4, ctx);
          bare = !(h.size() == 4 && le16(h.data() + 2) == 0x0a0d && pyc_version(le16(h.data())));
        } catch (const Error &) {
          bare = true;
        }
      }
      if (bare) restore(pc.entry, magic);
      if (auto v = pyc_version(magic)) e.content_kind = "pyc:" + v->str();
    }
    description_ = "PyInstaller archive, Python " + c->py.str() + (c->libname.empty() ? "" : " (" + c->libname + ")") +
                   ", " + summary_counts(*this);
    if (options) description_ += ", " + plural(options, "runtime option", "runtime options");
    if (deps) description_ += ", " + plural(deps, "dependency on another archive", "dependencies on other archives");
    if (c->old) description_ += ", PyInstaller 2.0's cookie";
  }

 private:
  std::string text_of(const Entry &e, const Context &ctx) const {
    auto b = head_entry(e, 4096, ctx);
    return std::string(reinterpret_cast<const char *>(b.data()), b.size());
  }
};

class Pyz final : public PycFileSystem {
 public:
  using PycFileSystem::PycFileSystem;

  void parse(const Context &ctx) {
    format_ = "pyz";
    const std::uint64_t size = src_->size();
    const auto h = src_->read_exact(0, 12, "the PYZ header");
    if (std::memcmp(h.data(), "PYZ\0", 4) != 0) throw Error("not a PYZ archive");
    const std::uint16_t magic = le16(h.data() + 4);
    auto v = pyc_version(magic);
    if (!v || le16(h.data() + 6) != 0x0a0d) throw Error("the PYZ's pyc magic number is unknown");
    const std::uint64_t toc = be32(h.data() + 8);
    if (toc < 12 || toc >= size) throw Error("the PYZ's table of contents lies outside it");
    if (size - toc > (256u << 20)) throw LimitError("the PYZ's table of contents is over 256 MiB");
    const auto t = src_->read_exact(toc, size - toc, "the PYZ's table of contents");
    std::size_t pos = 0;
    auto index = read_marshal(t, pos, v->major, v->minor, 16, 4ull * ctx.limits.max_entries + 16);
    // 3.x to 6.x: a list of (name, (typecode, offset, length)); 2.x: a dict
    // of name: (ispkg, offset, length).
    std::vector<std::pair<std::shared_ptr<const Marshal>, std::shared_ptr<const Marshal>>> items;
    if (index->type == Marshal::Type::list || index->type == Marshal::Type::tuple) {
      for (const auto &it : index->items)
        if (it->type == Marshal::Type::tuple && it->items.size() == 2) items.emplace_back(it->items[0], it->items[1]);
    } else if (index->type == Marshal::Type::dict) {
      for (std::size_t i = 0; i + 1 < index->items.size(); i += 2)
        items.emplace_back(index->items[i], index->items[i + 1]);
    } else {
      throw Error("the PYZ's table of contents isn't a list");
    }
    if (items.size() > ctx.limits.max_entries) throw LimitError("the PYZ lists too many modules");
    const bool dict = index->type == Marshal::Type::dict;
    TreeBuilder tree(*this, ctx.limits);
    std::uint64_t encrypted = 0, modules = 0;
    for (const auto &[k, val] : items) {
      ctx.check_cancelled();
      if (!k->is_text() || val->type != Marshal::Type::tuple || val->items.size() != 3) continue;
      const auto &f = val->items;
      if (f[0]->type != Marshal::Type::integer && f[0]->type != Marshal::Type::boolean) continue;
      if (f[1]->type != Marshal::Type::integer || f[2]->type != Marshal::Type::integer) continue;
      std::int64_t type = f[0]->type == Marshal::Type::boolean ? (f[0]->b ? 1 : 0) : f[0]->i;
      if (dict && type != 0) type = 1;
      const std::int64_t off = f[1]->i, len = f[2]->i;
      std::string path = k->s;
      if (type == 3) {  // a namespace package: a directory, no data
        std::replace(path.begin(), path.end(), '.', '/');
        Entry d;
        d.kind = Kind::directory;
        tree.add_path(path, d);
        continue;
      }
      Entry e;
      e.kind = Kind::file;
      e.size = UINT64_MAX;
      e.stored_size = len >= 0 ? static_cast<std::uint64_t>(len) : 0;
      if (off < 0 || len < 0 || static_cast<std::uint64_t>(off) > size ||
          static_cast<std::uint64_t>(len) > size - static_cast<std::uint64_t>(off)) {
        e.loc2 = UINT64_MAX;
        e.note = "its data lies outside the archive";
      } else {
        e.loc0 = static_cast<std::uint64_t>(off);
        e.loc1 = static_cast<std::uint64_t>(len);
        e.loc2 = 1 + static_cast<std::uint64_t>(Codec::zlib);
      }
      const bool data = type == 2;
      if (!data) {
        std::replace(path.begin(), path.end(), '.', '/');
        path += type == 1 ? "/__init__.pyc" : ".pyc";
      }
      // zlib's first byte (CMF 0x78): anything else is the old --key AES.
      if (e.loc2 != UINT64_MAX && e.loc1 > 0) {
        std::byte first{};
        if (src_->read(e.loc0, std::span(&first, 1)) == 1 && static_cast<std::uint8_t>(first) != 0x78) {
          e.loc2 = UINT64_MAX;
          e.note = "encrypted (PyInstaller before 6.0, --key): not read";
          ++encrypted;
        }
      }
      if (!data) e.content_kind = "pyc:" + v->str();
      const std::uint32_t i = tree.add_path(path, e);
      if (!data && e.loc2 != UINT64_MAX) restore(i, magic);
      ++modules;
    }
    tree.finish();
    description_ = "PyInstaller PYZ archive, Python " + v->str() + ", " + plural(modules, "module", "modules");
    if (encrypted) description_ += " (" + std::to_string(encrypted) + " encrypted)";
  }
};

}  // namespace

void PycFileSystem::restore(std::uint32_t entry, std::uint16_t magic) {
  magic_[entry] = magic;
  Entry &e = entries_[entry];
  if (e.size != UINT64_MAX) e.size += pyc_header(magic).size();
}

std::shared_ptr<Source> PycFileSystem::open(std::uint32_t entry, const Context &ctx) const {
  const std::uint32_t t = target_of(entry);
  auto it = magic_.find(t);
  if (it == magic_.end()) return SliceFileSystem::open(entry, ctx);
  const Entry &e = entries_.at(t);
  if (e.loc2 == UINT64_MAX) throw Error(display_name(e.name) + ": " + (e.note.empty() ? "unreadable" : e.note));
  Sink sink(ctx);
  sink.append(pyc_header(it->second));
  if (e.loc2 == 0) {
    auto s = slice(src_, e.loc0, e.loc1);
    std::vector<std::byte> buf(std::min<std::uint64_t>(e.loc1, 1u << 20));
    for (std::uint64_t at = 0; at < e.loc1;) {
      const std::size_t n = s->read(at, std::span(buf.data(), std::min<std::uint64_t>(buf.size(), e.loc1 - at)));
      if (n == 0) throw Error("short read");
      sink.append(std::span(buf.data(), n));
      at += n;
    }
  } else {
    decompress(static_cast<Codec>(e.loc2 - 1), *src_, e.loc0, e.loc1, sink, ctx);
  }
  if (e.size != UINT64_MAX && sink.size() != e.size)
    throw Error(display_name(e.name) + " decompresses to " + std::to_string(sink.size()) + " bytes, not " +
                std::to_string(e.size));
  return sink.finish();
}

std::vector<std::byte> PycFileSystem::head(std::uint32_t entry, std::uint64_t n, const Context &ctx) const {
  const std::uint32_t t = target_of(entry);
  auto it = magic_.find(t);
  if (it == magic_.end()) return SliceFileSystem::head(entry, n, ctx);
  std::vector<std::byte> out = pyc_header(it->second);
  const std::size_t hs = out.size();
  if (n > hs) {
    auto rest = head_entry(entries_.at(t), n - hs, ctx);
    out.insert(out.end(), rest.begin(), rest.end());
  }
  if (out.size() > n) out.resize(static_cast<std::size_t>(n));
  return out;
}

bool pyinstaller_payload(const Source &src) { return find_cookie(src).has_value(); }

bool pyz_header(std::span<const std::byte> b) {
  return b.size() >= 12 && std::memcmp(b.data(), "PYZ\0", 4) == 0 && le16(b.data() + 6) == 0x0a0d &&
         pyc_version(le16(b.data() + 4)).has_value();
}

std::shared_ptr<FileSystem> open_pyinstaller(std::shared_ptr<const Source> src, std::string_view, const Context &ctx) {
  auto fs = std::make_shared<CArchive>(std::move(src));
  fs->parse(ctx);
  return fs;
}

std::shared_ptr<FileSystem> open_pyz(std::shared_ptr<const Source> src, std::string_view, const Context &ctx) {
  auto fs = std::make_shared<Pyz>(std::move(src));
  fs->parse(ctx);
  return fs;
}

}  // namespace revkit::container::detail
