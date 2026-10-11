// tar: v7, ustar, GNU (long names and links, base-256 numbers) and pax
// (path, linkpath, size, mtime, uid, gid). Sparse members are listed but
// not read.
#include "formats.hh"

#include <charconv>

namespace revkit::container::detail {
namespace {

// An octal field, or GNU's base-256 (top bit of the first byte set).
std::uint64_t number(Buf &h, std::size_t off, std::size_t n, const char *what) {
  const auto first = h.u8(off);
  if (first & 0x80) {
    if (first & 0x40) throw Error(std::string("a negative tar ") + what);
    std::uint64_t v = first & 0x3f;
    for (std::size_t i = 1; i < n; ++i) {
      if (v >> 56) throw Error(std::string("a tar ") + what + " overflows");
      v = (v << 8) | h.u8(off + i);
    }
    return v;
  }
  std::uint64_t v = 0;
  bool digits = false;
  for (std::size_t i = 0; i < n; ++i) {
    const char c = static_cast<char>(h.u8(off + i));
    if (c == 0 || c == ' ') {
      if (digits) break;
      continue;
    }
    if (c < '0' || c > '7') throw Error(std::string("a malformed tar ") + what);
    if (v >> 60) throw Error(std::string("a tar ") + what + " overflows");
    v = v * 8 + static_cast<std::uint64_t>(c - '0');
    digits = true;
  }
  return v;
}

bool zero_block(std::span<const std::byte> b) {
  for (std::byte x : b)
    if (x != std::byte{0}) return false;
  return true;
}

bool checksum_ok(Buf &h) {
  std::uint64_t want = 0;
  try {
    want = number(h, 148, 8, "checksum");
  } catch (const Error &) {
    return false;
  }
  std::uint64_t mine = 0, signed_sum = 0;
  for (std::size_t i = 0; i < 512; ++i) {
    const std::uint8_t c = (i >= 148 && i < 156) ? ' ' : h.u8(i);
    mine += c;
    signed_sum += static_cast<std::uint64_t>(static_cast<std::int64_t>(static_cast<std::int8_t>(c)));
  }
  return want == mine || want == (signed_sum & 0x3ffff);
}

// "<len> key=value\n" records.
void pax(std::span<const std::byte> data, std::string &path, std::string &link, std::optional<std::uint64_t> &size,
         std::optional<std::int64_t> &mtime, std::optional<std::uint32_t> &uid, std::optional<std::uint32_t> &gid) {
  std::string_view s(reinterpret_cast<const char *>(data.data()), data.size());
  while (!s.empty()) {
    const std::size_t sp = s.find(' ');
    if (sp == std::string_view::npos) break;
    std::size_t len = 0;
    if (std::from_chars(s.data(), s.data() + sp, len).ec != std::errc() || len <= sp + 1 || len > s.size()) break;
    std::string_view rec = s.substr(sp + 1, len - sp - 1);
    s.remove_prefix(len);
    if (!rec.empty() && rec.back() == '\n') rec.remove_suffix(1);
    const std::size_t eq = rec.find('=');
    if (eq == std::string_view::npos) continue;
    const std::string_view key = rec.substr(0, eq), value = rec.substr(eq + 1);
    auto num = [&](auto &out) {
      std::uint64_t v = 0;
      if (std::from_chars(value.data(), value.data() + value.size(), v).ec == std::errc()) out = v;
    };
    if (key == "path") path = value;
    else if (key == "linkpath") link = value;
    else if (key == "size") num(size);
    else if (key == "uid") num(uid);
    else if (key == "gid") num(gid);
    else if (key == "mtime") {
      std::int64_t v = 0;
      if (std::from_chars(value.data(), value.data() + value.size(), v).ec == std::errc()) mtime = v;
    }
  }
}

class Tar final : public SliceFileSystem {
 public:
  using SliceFileSystem::SliceFileSystem;

  void parse(const Context &ctx) {
    format_ = "tar";
    TreeBuilder tree(*this, ctx.limits);
    const std::uint64_t size = src_->size();
    std::uint64_t off = 0;
    std::string long_name, long_link;
    std::string pax_path, pax_link;
    std::optional<std::uint64_t> pax_size;
    std::optional<std::int64_t> pax_mtime;
    std::optional<std::uint32_t> pax_uid, pax_gid;
    std::uint64_t headers = 0;
    bool ended = false;
    while (off + 512 <= size) {
      ctx.check_cancelled();
      const auto block = src_->read_exact(off, 512, "a tar header");
      if (zero_block(block)) {
        ended = true;
        break;
      }
      Buf h(block, "a tar header");
      if (!checksum_ok(h)) {
        if (headers == 0) throw Error("not a tar archive (bad header checksum)");
        warn("stopped at offset " + std::to_string(off) + ": not a tar header");
        break;
      }
      ++headers;
      const char type = static_cast<char>(h.u8(156));
      std::uint64_t msize = number(h, 124, 12, "size");
      if (pax_size) msize = *pax_size;
      const std::uint64_t data = off + 512;
      if (msize > size - data && !(type == '5' || type == '1' || type == '2')) {
        warn("the last member is truncated");
        if (data > size) break;
      }
      const std::uint64_t padded = (msize + 511) / 512 * 512;
      if (padded < msize || padded > UINT64_MAX - data) throw Error("a tar member size overflows");
      const std::uint64_t next = data + padded;
      // Metadata for the next member.
      if (type == 'L' || type == 'K' || type == 'x') {
        if (msize > (1u << 20)) throw LimitError("a tar extended header over 1 MiB");
        auto body = src_->read_exact(data, msize, "a tar extended header");
        if (type == 'x') {
          pax(body, pax_path, pax_link, pax_size, pax_mtime, pax_uid, pax_gid);
        } else {
          std::string s(reinterpret_cast<const char *>(body.data()), body.size());
          s.resize(strnlen(s.c_str(), s.size()));
          (type == 'L' ? long_name : long_link) = s;
        }
        off = next;
        continue;
      }
      if (type == 'g' || type == 'V' || type == 'M') {  // global header, volume label, multivolume
        off = next;
        continue;
      }
      std::string name = h.cstr(0, 100);
      if (h.str(257, 5) == "ustar") {
        const std::string prefix = h.cstr(345, 155);
        if (!prefix.empty() && h.str(257, 6) == std::string("ustar\0", 6)) name = prefix + "/" + name;
      }
      if (!long_name.empty()) name = long_name;
      if (!pax_path.empty()) name = pax_path;
      std::string link = h.cstr(157, 100);
      if (!long_link.empty()) link = long_link;
      if (!pax_link.empty()) link = pax_link;
      Entry e;
      e.mode = static_cast<std::uint32_t>(number(h, 100, 8, "mode") & 07777);
      e.has_mode = true;
      e.uid = pax_uid ? *pax_uid : static_cast<std::uint32_t>(number(h, 108, 8, "uid"));
      e.gid = pax_gid ? *pax_gid : static_cast<std::uint32_t>(number(h, 116, 8, "gid"));
      e.has_owner = true;
      e.mtime = pax_mtime ? *pax_mtime : static_cast<std::int64_t>(number(h, 136, 12, "mtime"));
      e.has_mtime = true;
      switch (type) {
        case '0':
        case '\0':
        case '7':
          e.kind = Kind::file;
          break;
        case '1': e.kind = Kind::hardlink; break;
        case '2': e.kind = Kind::symlink; break;
        case '3': e.kind = Kind::char_device; break;
        case '4': e.kind = Kind::block_device; break;
        case '5':
        case 'D':
          e.kind = Kind::directory;
          break;
        case '6': e.kind = Kind::fifo; break;
        case 'S':
          e.kind = Kind::file;
          e.note = "a GNU sparse member: not supported";
          break;
        default:
          e.kind = Kind::other;
          e.note = std::string("tar type '") + (type >= 0x20 && type < 0x7f ? std::string(1, type) : "?") + "'";
      }
      if (e.kind == Kind::directory && !name.empty() && name.back() == '/') name.pop_back();
      // Old archives mark directories by a trailing slash only.
      if (e.kind == Kind::file && !name.empty() && name.back() == '/') e.kind = Kind::directory;
      if (e.kind == Kind::file) {
        e.size = msize;
        e.stored_size = msize;
        e.loc0 = data;
        e.loc1 = msize;
        e.loc2 = (type == 'S' || data > size || msize > size - data) ? UINT64_MAX : 0;
        if (e.loc2 == UINT64_MAX && e.note.empty()) e.note = "truncated";
      } else if (e.kind == Kind::symlink || e.kind == Kind::hardlink) {
        e.link_target = link;
        e.size = link.size();
      }
      tree.add_path(name, std::move(e));
      long_name.clear();
      long_link.clear();
      pax_path.clear();
      pax_link.clear();
      pax_size.reset();
      pax_mtime.reset();
      pax_uid.reset();
      pax_gid.reset();
      if (next <= off) throw Error("a tar header doesn't advance");
      off = next;
    }
    if (headers == 0) throw Error("an empty tar archive");
    if (!ended && off + 512 > size && off < size) warn("the archive is truncated");
    tree.finish();
    description_ = "tar archive, " + summary_counts(*this);
  }
};

}  // namespace

std::shared_ptr<FileSystem> open_tar(std::shared_ptr<const Source> src, std::string_view, const Context &ctx) {
  auto fs = std::make_shared<Tar>(std::move(src));
  fs->parse(ctx);
  return fs;
}

}  // namespace revkit::container::detail
