// ISO 9660: the primary volume, Rock Ridge (names, modes, owners, times,
// symlinks, continuation areas, relocated directories) and Joliet (UCS-2
// names) when there is no Rock Ridge; multi-extent files. Version numbers
// (";1") and a bare trailing dot are dropped from plain ISO names.
#include "formats.hh"

#include <ctime>
#include <set>

namespace revkit::container::detail {
namespace {

std::int64_t record_time(std::span<const std::byte> t) {
  if (t.size() < 7) return 0;
  std::tm tm{};
  tm.tm_year = static_cast<std::uint8_t>(t[0]);
  tm.tm_mon = std::max(0, static_cast<int>(static_cast<std::uint8_t>(t[1])) - 1);
  tm.tm_mday = std::max(1, static_cast<int>(static_cast<std::uint8_t>(t[2])));
  tm.tm_hour = static_cast<std::uint8_t>(t[3]);
  tm.tm_min = static_cast<std::uint8_t>(t[4]);
  tm.tm_sec = static_cast<std::uint8_t>(t[5]);
  const int gmt = static_cast<std::int8_t>(t[6]);
  return static_cast<std::int64_t>(timegm(&tm)) - gmt * 15 * 60;
}

// UCS-2 big-endian (Joliet) to UTF-8.
std::string ucs2be(std::span<const std::byte> s) {
  std::string out;
  for (std::size_t i = 0; i + 1 < s.size(); i += 2) {
    const std::uint32_t c = static_cast<std::uint32_t>(s[i]) << 8 | static_cast<std::uint32_t>(s[i + 1]);
    if (c < 0x80) {
      out += static_cast<char>(c);
    } else if (c < 0x800) {
      out += static_cast<char>(0xc0 | (c >> 6));
      out += static_cast<char>(0x80 | (c & 0x3f));
    } else {
      out += static_cast<char>(0xe0 | (c >> 12));
      out += static_cast<char>(0x80 | ((c >> 6) & 0x3f));
      out += static_cast<char>(0x80 | (c & 0x3f));
    }
  }
  return out;
}

struct Record {
  std::uint32_t extent = 0;
  std::uint32_t length = 0;
  std::uint8_t flags = 0;
  std::string name;  // raw identifier
  std::int64_t mtime = 0;
  std::span<const std::byte> su;  // system use area
};

class Iso final : public FileSystem {
 public:
  explicit Iso(std::shared_ptr<const Source> src) : src_(std::move(src)) {}

  void parse(const Context &ctx) {
    format_ = "iso9660";
    std::vector<std::byte> pvd, joliet;
    for (std::uint64_t sector = 16; sector < 16 + 64; ++sector) {
      const auto vd = src_->read_exact(sector * 2048, 2048, "an ISO 9660 volume descriptor");
      if (std::string(reinterpret_cast<const char *>(vd.data() + 1), 5) != "CD001") break;
      const auto type = static_cast<std::uint8_t>(vd[0]);
      if (type == 255) break;
      if (type == 1 && pvd.empty()) pvd = vd;
      if (type == 2 && vd[88] == std::byte{'%'} && vd[89] == std::byte{'/'} &&
          (vd[90] == std::byte{'@'} || vd[90] == std::byte{'C'} || vd[90] == std::byte{'E'}))
        joliet = vd;
    }
    if (pvd.empty()) throw Error("no ISO 9660 primary volume descriptor");
    Buf p(pvd, "the ISO 9660 primary volume descriptor");
    lbs_ = p.l16(128);
    if (lbs_ != 512 && lbs_ != 1024 && lbs_ != 2048) throw Error("an ISO 9660 block size of " + std::to_string(lbs_));
    volume_ = p.str(40, 32);
    while (!volume_.empty() && volume_.back() == ' ') volume_.pop_back();
    const Record root = record(std::span(pvd).subspan(156, 34));
    // Rock Ridge: the root's "." entry carries SUSP ("SP") or RR fields.
    const auto first = src_->read_exact(static_cast<std::uint64_t>(root.extent) * lbs_, std::min<std::uint32_t>(root.length, lbs_),
                                        "the ISO 9660 root directory");
    if (!first.empty() && static_cast<std::uint8_t>(first[0]) >= 34) {
      const Record dot = record(std::span(first).first(static_cast<std::uint8_t>(first[0])));
      rock_ = has_rock(dot.su);
    }
    Record top = root;
    std::string flavor = rock_ ? "Rock Ridge" : "plain";
    if (!rock_ && !joliet.empty()) {
      top = record(std::span(joliet).subspan(156, 34));
      joliet_ = true;
      flavor = "Joliet";
    }
    TreeBuilder tree(*this, ctx.limits);
    std::set<std::uint32_t> seen;
    entries_[0].mtime = top.mtime;
    entries_[0].has_mtime = true;
    walk(tree, 0, top, seen, ctx, 0);
    tree.finish();
    description_ = "ISO 9660 image (" + flavor + ")" + (volume_.empty() ? "" : " \"" + display_name(volume_) + "\"") +
                   ", " + summary_counts(*this);
  }

  std::shared_ptr<Source> open(std::uint32_t entry, const Context &) const override {
    const Entry *e = &entries_.at(entry);
    if (e->kind == Kind::symlink || e->kind == Kind::hardlink) {
      auto t = resolve_link(entry);
      if (!t) throw Error("a link whose target isn't in the image");
      e = &entries_.at(*t);
    }
    if (e->kind != Kind::file) throw Error(display_name(e->name) + " is not a file");
    return mapped_source(src_, extents_.at(e->loc0), e->size);
  }

 private:
  Record record(std::span<const std::byte> r) const {
    Buf b(r, "an ISO 9660 directory record");
    Record out;
    const std::uint8_t len = b.u8(0);
    if (len < 34 || len > r.size()) throw Error("a malformed ISO 9660 directory record");
    out.extent = b.l32(2);
    out.length = b.l32(10);
    out.mtime = record_time(b.span(18, 7));
    out.flags = b.u8(25);
    const std::uint8_t nlen = b.u8(32);
    if (33u + nlen > len) throw Error("an ISO 9660 name runs past its record");
    out.name = b.str(33, nlen);
    std::size_t su = 33u + nlen + ((nlen & 1) ? 0 : 1);
    if (su < len) out.su = r.subspan(su, len - su);
    return out;
  }

  static bool has_rock(std::span<const std::byte> su) {
    for (std::size_t p = 0; p + 4 <= su.size();) {
      const std::string sig(reinterpret_cast<const char *>(su.data() + p), 2);
      const std::uint8_t len = static_cast<std::uint8_t>(su[p + 2]);
      if (sig == "SP" || sig == "RR" || sig == "PX" || sig == "NM") return true;
      if (len < 4) break;
      p += len;
    }
    return false;
  }

  struct Rock {
    std::string name;
    bool has_name = false;
    std::uint32_t mode = 0, uid = 0, gid = 0;
    bool has_mode = false;
    std::string symlink;
    bool is_symlink = false;
    std::int64_t mtime = 0;
    bool has_mtime = false;
    bool relocated = false;  // RE: shown where its CL points
    std::uint32_t child_link = 0;  // CL
  };

  // Rock Ridge fields of a record, following continuation areas (CE): 64
  // KiB of them in all, and names and link targets of at most 4 KiB (a CE
  // pointing at itself repeated its NM fields into a 1 MiB name per record).
  static constexpr std::size_t kMaxRockText = 4096;
  void rock(std::span<const std::byte> su, Rock &r, int hops = 0, std::uint32_t ce_budget = 65536) const {
    std::uint32_t ce_block = 0, ce_off = 0, ce_len = 0;
    for (std::size_t p = 0; p + 4 <= su.size();) {
      const std::string sig(reinterpret_cast<const char *>(su.data() + p), 2);
      const std::uint8_t len = static_cast<std::uint8_t>(su[p + 2]);
      if (len < 4 || p + len > su.size()) break;
      Buf f(su.subspan(p, len), "a Rock Ridge field");
      if (sig == "NM" && len >= 5) {
        const std::uint8_t flags = f.u8(4);
        if (!(flags & 0x6)) r.name += f.str(5, len - 5u);  // not "." or ".."
        if (r.name.size() > kMaxRockText) r.name.resize(kMaxRockText);
        r.has_name = true;
      } else if (sig == "PX" && len >= 36) {
        r.mode = f.l32(4);
        r.uid = f.l32(20);
        r.gid = f.l32(28);
        r.has_mode = true;
      } else if (sig == "SL" && len >= 5) {
        r.is_symlink = true;
        std::size_t q = 5;
        while (q + 2 <= len) {
          const std::uint8_t cflags = f.u8(q), clen = f.u8(q + 1);
          if (q + 2u + clen > len) break;
          std::string comp;
          if (cflags & 0x2) comp = ".";
          else if (cflags & 0x4) comp = "..";
          else if (cflags & 0x8) comp = "";  // the root
          else comp = f.str(q + 2, clen);
          if (!r.symlink.empty() && r.symlink.back() != '/') r.symlink += '/';
          if (cflags & 0x8) r.symlink = "/";
          else r.symlink += comp;
          if (r.symlink.size() > kMaxRockText) r.symlink.resize(kMaxRockText);
          q += 2u + clen;
        }
      } else if (sig == "TF" && len >= 5) {
        const std::uint8_t flags = f.u8(4);
        const bool long_form = flags & 0x80;
        const std::size_t width = long_form ? 17 : 7;
        std::size_t q = 5;
        if (flags & 0x1) q += width;  // creation
        if ((flags & 0x2) && q + width <= len && !long_form) {
          r.mtime = record_time(f.span(q, 7));
          r.has_mtime = true;
        }
      } else if (sig == "CE" && len >= 28) {
        ce_block = f.l32(4);
        ce_off = f.l32(12);
        ce_len = f.l32(20);
      } else if (sig == "RE") {
        r.relocated = true;
      } else if (sig == "CL" && len >= 12) {
        r.child_link = f.l32(4);
      } else if (sig == "ST") {
        break;
      }
      p += len;
    }
    if (ce_len && hops < 16 && ce_len <= ce_budget) {
      const auto more = src_->read_exact(static_cast<std::uint64_t>(ce_block) * lbs_ + ce_off, ce_len, "a Rock Ridge continuation");
      rock(more, r, hops + 1, ce_budget - ce_len);
    }
  }

  std::string plain_name(const std::string &id) const {
    std::string n = id;
    if (joliet_) n = ucs2be(std::as_bytes(std::span(id.data(), id.size())));
    if (const auto semi = n.rfind(';'); semi != std::string::npos) n.resize(semi);
    if (!n.empty() && n.back() == '.') n.pop_back();
    return n;
  }

  void walk(TreeBuilder &tree, std::uint32_t parent, const Record &dir, std::set<std::uint32_t> &seen, const Context &ctx,
            unsigned depth) {
    if (depth > ctx.limits.max_dir_depth) throw LimitError("ISO 9660 directories nest too deep");
    if (!seen.insert(dir.extent).second) throw Error("an ISO 9660 directory contains itself");
    if (dir.length > (64u << 20)) throw LimitError("an ISO 9660 directory over 64 MiB");
    auto data = src_->read_exact(static_cast<std::uint64_t>(dir.extent) * lbs_, dir.length, "an ISO 9660 directory");
    // Subdirectories are read after this one is released: directories may
    // overlap, and 256 levels of 64 MiB each were held at once.
    std::vector<std::pair<std::uint32_t, Record>> subdirs;
    std::size_t p = 0;
    std::vector<Run> pending;  // a multi-extent file's pieces so far
    std::uint64_t pending_size = 0;
    while (p < data.size()) {
      ctx.check_cancelled();
      const std::uint8_t len = static_cast<std::uint8_t>(data[p]);
      if (len == 0) {
        p = (p / lbs_ + 1) * lbs_;  // the rest of the block is padding
        continue;
      }
      if (p + len > data.size()) break;
      const Record r = record(std::span(data).subspan(p, len));
      p += len;
      if (r.name.size() == 1 && (r.name[0] == '\0' || r.name[0] == '\1')) continue;  // "." and ".."
      Rock rr;
      if (rock_) rock(r.su, rr);
      if (rr.relocated) continue;
      std::string name = rock_ && rr.has_name ? rr.name : plain_name(r.name);
      if (name.empty() || name == "." || name == "..") continue;
      Entry e;
      e.name = name;
      e.mtime = rr.has_mtime ? rr.mtime : r.mtime;
      e.has_mtime = true;
      if (rr.has_mode) {
        e.mode = rr.mode & 07777;
        e.has_mode = true;
        e.uid = rr.uid;
        e.gid = rr.gid;
        e.has_owner = true;
      }
      const bool directory = (r.flags & 0x2) || rr.child_link;
      if (rr.is_symlink) {
        e.kind = Kind::symlink;
        e.link_target = rr.symlink;
        e.size = rr.symlink.size();
      } else if (directory) {
        e.kind = Kind::directory;
      } else {
        e.kind = Kind::file;
        pending.push_back({pending_size, static_cast<std::uint64_t>(r.extent) * lbs_, r.length, false});
        pending_size += r.length;
        if (r.flags & 0x80) continue;  // more extents follow under the same name
        e.size = pending_size;
        e.loc0 = extents_.size();
        extents_.push_back(std::move(pending));
        pending.clear();
        pending_size = 0;
      }
      const std::uint32_t idx = tree.add_child(parent, std::move(e));
      if (directory && !rr.is_symlink) {
        Record sub = r;
        if (rr.child_link) {
          // The relocated directory: its own "." record says how long it is.
          sub.extent = rr.child_link;
          const auto first = src_->read_exact(static_cast<std::uint64_t>(sub.extent) * lbs_, 34, "a relocated directory");
          sub.length = le32(first.data() + 10);
        }
        sub.su = {};
        subdirs.emplace_back(idx, std::move(sub));
      }
    }
    std::vector<std::byte>().swap(data);
    for (const auto &[idx, sub] : subdirs) walk(tree, idx, sub, seen, ctx, depth + 1);
  }

  std::shared_ptr<const Source> src_;
  std::uint32_t lbs_ = 2048;
  bool rock_ = false, joliet_ = false;
  std::string volume_;
  std::vector<std::vector<Run>> extents_;
};

}  // namespace

std::shared_ptr<FileSystem> open_iso9660(std::shared_ptr<const Source> src, std::string_view, const Context &ctx) {
  auto fs = std::make_shared<Iso>(std::move(src));
  fs->parse(ctx);
  return fs;
}

}  // namespace revkit::container::detail
