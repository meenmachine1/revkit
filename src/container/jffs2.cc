// JFFS2, the journalling flash file system, in either byte order (read-only):
// the image is a log of nodes (docs/filesystems.md). Every node found at a
// 4-byte boundary whose header CRC holds is read; inode nodes carry a
// piece of a file (or its metadata) and directory entries a name, each
// with a version, and the newest version wins: the newest entry of a name
// in a directory decides what it is (an inode number of 0 deletes it), the
// newest inode node a file's mode, owner, time and size, and data nodes
// are laid over each other oldest first. Data is stored plainly, as zeros
// (holes), or compressed with zlib, rtime or LZO; the rarer compressors
// (rubin, dynrubin, LZMA) are named and not read.
#include "formats.hh"

#include <algorithm>
#include <map>
#include <set>
#include <unordered_map>

namespace revkit::container::detail {
namespace {

constexpr std::uint16_t kMagic = 0x1985;
constexpr std::uint16_t kDirent = 0xe001, kInode = 0xe002;
constexpr std::uint32_t kRootIno = 1;
constexpr std::size_t kMaxNodes = 4u << 20;
constexpr std::uint32_t kMaxNode = 1u << 20;

// JFFS2's CRC: CRC-32 with a seed of 0 and no final inversion.
std::uint32_t jcrc(std::span<const std::byte> b) { return crc32_ieee(b, 0xffffffffu) ^ 0xffffffffu; }

enum Compr : std::uint8_t { kNone = 0, kZero = 1, kRtime = 2, kRubinMips = 3, kCopy = 4, kDynRubin = 5, kZlib = 6, kLzo = 7, kLzma = 8 };

const char *compr_name(std::uint8_t c) {
  switch (c) {
    case kNone: return "none";
    case kZero: return "zero";
    case kRtime: return "rtime";
    case kRubinMips: return "rubinmips";
    case kCopy: return "copy";
    case kDynRubin: return "dynrubin";
    case kZlib: return "zlib";
    case kLzo: return "lzo";
    case kLzma: return "lzma";
    default: return "unknown";
  }
}

// rtime: a byte, then how many bytes to copy from where that byte value
// was last seen.
void rtime_decode(std::span<const std::byte> in, std::span<std::byte> out) {
  std::size_t positions[256] = {};
  std::size_t o = 0, p = 0;
  while (o < out.size()) {
    if (p + 2 > in.size()) throw Error("truncated rtime data");
    const auto value = static_cast<std::uint8_t>(in[p++]);
    std::size_t repeat = static_cast<std::uint8_t>(in[p++]);
    out[o++] = static_cast<std::byte>(value);
    std::size_t back = positions[value];
    positions[value] = o;
    if (repeat > out.size() - o) throw Error("rtime data decodes past its size");
    for (; repeat; --repeat) out[o++] = out[back++];
  }
}

struct DataNode {
  std::uint32_t version = 0, offset = 0, dsize = 0, csize = 0, isize = 0;
  std::uint64_t phys = 0;  // the compressed data in the image
  std::uint8_t compr = 0;
};

struct Ino {
  std::uint32_t version = 0;
  bool has_meta = false;
  std::uint32_t mode = 0, uid = 0, gid = 0, mtime = 0, isize = 0;
  std::vector<DataNode> nodes;
};

struct Dirent {
  std::uint32_t version = 0, ino = 0;
  std::uint8_t type = 0;
};

Kind dt_kind(std::uint8_t t) {
  switch (t) {
    case 1: return Kind::fifo;
    case 2: return Kind::char_device;
    case 4: return Kind::directory;
    case 6: return Kind::block_device;
    case 8: return Kind::file;
    case 10: return Kind::symlink;
    case 12: return Kind::socket;
    default: return Kind::other;
  }
}

class Jffs2 final : public FileSystem {
 public:
  explicit Jffs2(std::shared_ptr<const Source> src) : src_(std::move(src)) {}

  void parse(const Context &ctx) {
    format_ = "jffs2";
    scan(ctx);
    // Each name's newest entry, by directory.
    std::unordered_map<std::uint32_t, std::vector<std::pair<std::string, Dirent>>> children;
    for (auto &[key, d] : dirents_)
      if (d.ino != 0) children[key.first].emplace_back(key.second, d);
    dirents_.clear();
    TreeBuilder tree(*this, ctx.limits);
    if (auto r = inodes_.find(kRootIno); r != inodes_.end() && r->second.has_meta) {
      entries_[0].mode = r->second.mode & 07777;
      entries_[0].has_mode = true;
    }
    std::set<std::uint32_t> seen{kRootIno};
    // Breadth first: (directory ino, its entry).
    std::vector<std::pair<std::uint32_t, std::uint32_t>> queue{{kRootIno, 0}};
    std::uint64_t orphans = 0;
    for (std::size_t q = 0; q < queue.size(); ++q) {
      ctx.check_cancelled();
      auto [dino, didx] = queue[q];
      auto it = children.find(dino);
      if (it == children.end()) continue;
      for (auto &[name, d] : it->second) {
        if (name.empty() || name == "." || name == "..") continue;
        Entry e;
        e.name = name;
        const Ino *ino = nullptr;
        if (auto f = inodes_.find(d.ino); f != inodes_.end()) ino = &f->second;
        e.kind = ino && ino->has_meta ? mode_kind(ino->mode) : dt_kind(d.type);
        if (ino && ino->has_meta) {
          e.mode = ino->mode & 07777;
          e.has_mode = true;
          e.uid = ino->uid;
          e.gid = ino->gid;
          e.has_owner = true;
          e.mtime = ino->mtime;
          e.has_mtime = true;
        }
        e.loc0 = d.ino;
        if (e.kind == Kind::file) {
          e.size = ino ? ino->isize : 0;
          std::uint64_t stored = 0;
          if (ino)
            for (const DataNode &n : ino->nodes) stored += n.csize;
          e.stored_size = stored;
          if (ino) {
            for (const DataNode &n : ino->nodes)
              if (n.compr != kNone && n.compr != kZero && n.compr != kZlib && n.compr != kRtime && n.compr != kLzo &&
                  n.dsize) {
                e.note = std::string(compr_name(n.compr)) + " compression is not supported";
                e.loc2 = UINT64_MAX;
                break;
              }
          }
        } else if (e.kind == Kind::symlink) {
          try {
            e.link_target = text(d.ino, ctx);
            e.size = e.link_target.size();
          } catch (const Error &err) {
            e.note = std::string("unreadable link: ") + err.what();
          }
        }
        const bool dir = e.kind == Kind::directory;
        const std::uint32_t idx = tree.add_child(didx, std::move(e));
        if (dir) {
          if (!seen.insert(d.ino).second) {
            warn("directory inode " + std::to_string(d.ino) + " is listed twice: its second listing is empty");
            continue;
          }
          queue.emplace_back(d.ino, idx);
        }
      }
    }
    for (const auto &[pino, list] : children)
      if (!seen.count(pino)) orphans += list.size();
    if (orphans) warn(plural(orphans, "entry is", "entries are") + " in directories no path reaches");
    tree.finish();
    std::string comprs;
    for (const auto &[c, n] : compr_used_) comprs += std::string(comprs.empty() ? "" : ", ") + compr_name(c);
    description_ = std::string("JFFS2, ") + (be_ ? "big" : "little") + "-endian" +
                   (comprs.empty() ? "" : ", " + comprs) + ", " + summary_counts(*this);
  }

  std::shared_ptr<Source> open(std::uint32_t entry, const Context &ctx) const override {
    const Entry &e = file_entry(entry);
    Sink sink(ctx);
    data(e.loc0, sink, ctx);
    return sink.finish();
  }

  std::vector<std::byte> head(std::uint32_t entry, std::uint64_t n, const Context &ctx) const override {
    const Entry &e = file_entry(entry);
    Sink sink(ctx, n);
    data(e.loc0, sink, ctx);
    return sink.finish()->head(n);
  }

 private:
  const Entry &file_entry(std::uint32_t entry) const {
    const Entry *e = &entries_.at(entry);
    if (e->kind == Kind::symlink) {
      auto t = resolve_link(entry);
      if (!t) throw Error("a link whose target isn't in the image");
      e = &entries_.at(*t);
    }
    if (e->kind != Kind::file) throw Error(display_name(e->name) + " is not a file");
    if (e->loc2 == UINT64_MAX) throw Error(display_name(e->name) + ": " + e->note);
    return *e;
  }

  std::uint16_t u16(const std::byte *p) const { return be_ ? be16(p) : le16(p); }
  std::uint32_t u32(const std::byte *p) const { return be_ ? be32(p) : le32(p); }

  // Every node in the image.
  void scan(const Context &ctx) {
    WindowReader rd(*src_);
    const std::uint64_t size = src_->size();
    bool order_known = false;
    std::uint64_t bad = 0, nodes = 0;
    for (std::uint64_t p = 0; p + 12 <= size;) {
      if ((p & 0xfffff) == 0) ctx.check_cancelled();
      auto h = rd.get(p, 12);
      if (h.size() < 12) break;
      const std::uint16_t le_magic = le16(h.data()), be_magic = be16(h.data());
      if (le_magic != kMagic && be_magic != kMagic) {
        p += 4;
        continue;
      }
      const bool be = le_magic != kMagic;
      if (order_known && be != be_) {
        p += 4;
        continue;
      }
      const bool was = be_;
      be_ = be;
      const std::uint32_t totlen = u32(h.data() + 4);
      if (jcrc(h.first(8)) != u32(h.data() + 8) || totlen < 12 || totlen > kMaxNode) {
        be_ = was;
        p += 4;
        continue;
      }
      order_known = true;
      if (totlen > size - p) {
        warn("a node at " + std::to_string(p) + " runs past the image");
        break;
      }
      if (++nodes > kMaxNodes) throw LimitError("a JFFS2 image of over 4 million nodes");
      const std::uint16_t type = u16(h.data() + 2);
      if (type == kInode || type == kDirent) {
        auto n = rd.get(p, totlen);
        if (!(type == kInode ? inode_node(n, p) : dirent_node(n))) ++bad;
      }
      p += (totlen + 3u) & ~3ull;
    }
    if (!order_known) throw Error("no JFFS2 nodes in the image");
    if (bad) warn(plural(bad, "node fails its CRC and was", "nodes fail their CRC and were") + " skipped");
    // Data nodes oldest first; the newest gives the size.
    for (auto &[ino, i] : inodes_)
      std::stable_sort(i.nodes.begin(), i.nodes.end(),
                       [](const DataNode &a, const DataNode &b) { return a.version < b.version; });
  }

  bool inode_node(std::span<const std::byte> n, std::uint64_t at) {
    if (n.size() < 68) return false;
    if (jcrc(n.first(60)) != u32(n.data() + 64)) return false;
    DataNode d;
    const std::uint32_t ino = u32(n.data() + 12);
    d.version = u32(n.data() + 16);
    const std::uint32_t mode = u32(n.data() + 20);
    d.isize = u32(n.data() + 28);
    const std::uint32_t mtime = u32(n.data() + 36);
    d.offset = u32(n.data() + 44);
    d.csize = u32(n.data() + 48);
    d.dsize = u32(n.data() + 52);
    d.compr = static_cast<std::uint8_t>(n[56]);
    if (d.compr == kZero) d.csize = 0;
    if (d.csize > n.size() - 68) return false;
    if (d.csize && jcrc(n.subspan(68, d.csize)) != u32(n.data() + 60)) return false;
    if (d.dsize > (1u << 20) || std::uint64_t{d.offset} + d.dsize > (1ull << 32)) return false;
    d.phys = at + 68;
    Ino &i = inodes_[ino];
    if (!i.has_meta || d.version >= i.version) {
      i.version = d.version;
      i.has_meta = true;
      i.mode = mode;
      i.uid = u16(n.data() + 24);
      i.gid = u16(n.data() + 26);
      i.mtime = mtime;
      i.isize = d.isize;
    }
    if (d.dsize && d.compr != kZero && d.compr != kNone) ++compr_used_[d.compr];
    i.nodes.push_back(d);
    return true;
  }

  bool dirent_node(std::span<const std::byte> n) {
    if (n.size() < 40) return false;
    if (jcrc(n.first(32)) != u32(n.data() + 32)) return false;
    const std::uint8_t nsize = static_cast<std::uint8_t>(n[28]);
    if (40u + nsize > n.size()) return false;
    const auto name = n.subspan(40, nsize);
    if (jcrc(name) != u32(n.data() + 36)) return false;
    const std::uint32_t pino = u32(n.data() + 12);
    Dirent d;
    d.version = u32(n.data() + 16);
    d.ino = u32(n.data() + 20);
    d.type = static_cast<std::uint8_t>(n[29]);
    auto key = std::make_pair(pino, std::string(reinterpret_cast<const char *>(name.data()), name.size()));
    auto [it, fresh] = dirents_.try_emplace(std::move(key), d);
    if (!fresh && d.version >= it->second.version) it->second = d;
    return true;
  }

  // One node's data, decompressed.
  std::vector<std::byte> node_data(const DataNode &d) const {
    std::vector<std::byte> out(d.dsize);
    if (d.compr == kZero || d.dsize == 0) return out;
    const auto in = src_->read_exact(d.phys, d.csize, "JFFS2 node data");
    switch (d.compr) {
      case kNone:
      case kCopy:
        if (in.size() < d.dsize) throw Error("a JFFS2 node's data is short");
        std::memcpy(out.data(), in.data(), d.dsize);
        break;
      case kZlib:
        if (decompress_block(Codec::zlib, in, out) != d.dsize) throw Error("a JFFS2 zlib node decodes short");
        break;
      case kRtime: rtime_decode(in, out); break;
      case kLzo: {
        std::vector<std::byte> dec;
        lzo1x_decode(in, dec, d.dsize);
        if (dec.size() != d.dsize) throw Error("a JFFS2 LZO node decodes short");
        out = std::move(dec);
        break;
      }
      default: throw Error(std::string("JFFS2 ") + compr_name(d.compr) + " compression is not supported");
    }
    return out;
  }

  struct Frag {
    std::uint64_t end = 0;
    std::size_t node = 0;   // index into the inode's nodes
    std::uint64_t src = 0;  // offset in the node's data
  };

  // Removes [a, b) from the map, splitting what straddles its ends.
  static void punch(std::map<std::uint64_t, Frag> &m, std::uint64_t a, std::uint64_t b) {
    auto it = m.lower_bound(a);
    if (it != m.begin()) {
      auto prev = std::prev(it);
      if (prev->second.end > a) {
        const Frag f = prev->second;
        const std::uint64_t start = prev->first;
        prev->second.end = a;
        if (f.end > b) {
          Frag right = f;
          right.src += b - start;
          m.emplace(b, right);
          return;
        }
      }
    }
    it = m.lower_bound(a);
    while (it != m.end() && it->first < b) {
      if (it->second.end <= b) {
        it = m.erase(it);
        continue;
      }
      Frag right = it->second;
      right.src += b - it->first;
      m.erase(it);
      m.emplace(b, right);
      break;
    }
  }

  // A file's bytes: its data nodes laid over each other, oldest first, cut
  // to the size each says the file had.
  void data(std::uint32_t ino_no, Sink &sink, const Context &ctx) const {
    auto it = inodes_.find(ino_no);
    if (it == inodes_.end()) return;
    const Ino &ino = it->second;
    std::map<std::uint64_t, Frag> m;
    std::uint64_t size = 0;
    for (std::size_t k = 0; k < ino.nodes.size(); ++k) {
      const DataNode &d = ino.nodes[k];
      if (d.isize < size) punch(m, d.isize, UINT64_MAX);
      if (d.dsize) {
        punch(m, d.offset, std::uint64_t{d.offset} + d.dsize);
        m.emplace(d.offset, Frag{std::uint64_t{d.offset} + d.dsize, k, 0});
      }
      size = d.isize;
    }
    punch(m, size, UINT64_MAX);
    std::uint64_t pos = 0;
    std::size_t cached = SIZE_MAX;
    std::vector<std::byte> buf;
    auto zeros = [&](std::uint64_t n) {
      static const std::vector<std::byte> z(65536);
      while (n && !sink.full()) {
        const std::size_t k = static_cast<std::size_t>(std::min<std::uint64_t>(n, z.size()));
        sink.append(std::span(z).first(k));
        n -= k;
      }
    };
    for (const auto &[start, f] : m) {
      ctx.check_cancelled();
      if (sink.full()) return;
      if (start > pos) zeros(start - pos);
      if (f.node != cached) {
        buf = node_data(ino.nodes[f.node]);
        cached = f.node;
      }
      const std::uint64_t len = f.end - start;
      if (f.src + len > buf.size()) throw Error("a JFFS2 fragment lies outside its node");
      sink.append(std::span(buf).subspan(static_cast<std::size_t>(f.src), static_cast<std::size_t>(len)));
      pos = f.end;
    }
    if (size > pos) zeros(size - pos);
  }

  std::string text(std::uint32_t ino, const Context &) const {
    Context small;
    small.limits.max_file_bytes = 8192;
    Sink sink(small);
    data(ino, sink, small);
    auto s = sink.finish();
    const auto t = s->read_exact(0, s->size(), "a JFFS2 symlink");
    return std::string(reinterpret_cast<const char *>(t.data()), t.size());
  }

  std::shared_ptr<const Source> src_;
  bool be_ = false;
  std::unordered_map<std::uint32_t, Ino> inodes_;
  std::map<std::pair<std::uint32_t, std::string>, Dirent> dirents_;
  std::map<std::uint8_t, std::uint64_t> compr_used_;
};

}  // namespace

bool jffs2_header(std::span<const std::byte> b) {
  if (b.size() < 12) return false;
  const bool le = le16(b.data()) == kMagic, be = be16(b.data()) == kMagic;
  if (!le && !be) return false;
  const std::uint16_t type = be ? be16(b.data() + 2) : le16(b.data() + 2);
  const std::uint32_t crc = be ? be32(b.data() + 8) : le32(b.data() + 8);
  const std::uint32_t totlen = be ? be32(b.data() + 4) : le32(b.data() + 4);
  static constexpr std::uint16_t kTypes[] = {0xe001, 0xe002, 0x2003, 0x2004, 0x2006, 0xe008, 0xe009};
  return std::find(std::begin(kTypes), std::end(kTypes), type) != std::end(kTypes) && totlen >= 12 &&
         jcrc(b.first(8)) == crc;
}

std::shared_ptr<FileSystem> open_jffs2(std::shared_ptr<const Source> src, std::string_view, const Context &ctx) {
  auto fs = std::make_shared<Jffs2>(std::move(src));
  fs->parse(ctx);
  return fs;
}

}  // namespace revkit::container::detail
