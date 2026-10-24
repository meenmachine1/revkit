// YAFFS2 images as NAND dumps and image tools write them (read-only;
// docs/filesystems.md): pages of data, each followed by its spare (OOB)
// area holding the packed tags (sequence number, object, chunk, byte
// count), or with the tags at the end of the page ("inband tags", no
// spare). Nothing marks the format, so the geometry is guessed: the
// common page and spare sizes (2 KiB + 64, 4 KiB + 128 or 224, 8 KiB +
// 256 or 448, 16 KiB + 1280, 512 + 16, 1 KiB + 32, and inband pages), the
// tags at the spare's start or after a 2-byte bad-block marker, either
// byte order, scored by how many chunks of the first blocks read as tags
// and object headers. Of each chunk the copy with the highest sequence
// number wins (the later page within a block); an object's newest header
// gives its name, parent, type, mode and size.
#include "formats.hh"

#include <algorithm>
#include <map>
#include <set>
#include <unordered_map>

namespace revkit::container::detail {
namespace {

constexpr std::uint32_t kLowestSeq = 0x00001000, kHighestSeq = 0xefffff00;
constexpr std::uint32_t kExtraHeader = 0x80000000u, kAllExtra = 0xf0000000u;
constexpr std::uint32_t kRootId = 1, kLostFound = 2, kUnlinked = 3, kDeleted = 4;
constexpr std::size_t kMaxChunks = 16u << 20;

enum ObjType : std::uint32_t { kFile = 1, kSymlink = 2, kDirectory = 3, kHardlink = 4, kSpecial = 5 };

struct Geometry {
  std::uint32_t page = 0, spare = 0, tag_off = 0;
  bool inband = false, be = false;
  std::uint32_t stride() const { return page + spare; }
  std::uint32_t data() const { return inband ? page - 16 : page; }
};

struct Tags {
  std::uint32_t seq = 0, obj = 0, chunk = 0, nbytes = 0;
  bool header = false;
};

std::uint32_t rd32(const std::byte *p, bool be) { return be ? be32(p) : le32(p); }

// The tags of the chunk whose page starts at `chunk`, if they are tags.
std::optional<Tags> tags_of(std::span<const std::byte> chunk, const Geometry &g) {
  const std::size_t at = g.inband ? g.page - 16 : g.page + g.tag_off;
  if (at + 16 > chunk.size()) return std::nullopt;
  const std::byte *p = chunk.data() + at;
  Tags t;
  t.seq = rd32(p, g.be);
  t.obj = rd32(p + 4, g.be);
  t.chunk = rd32(p + 8, g.be);
  t.nbytes = rd32(p + 12, g.be);
  if (t.seq < kLowestSeq || t.seq > kHighestSeq) return std::nullopt;
  if (t.chunk & kExtraHeader) {
    t.header = true;
    t.chunk = 0;
    t.obj &= ~kAllExtra;
  } else {
    t.header = t.chunk == 0;
    if (!t.header && t.nbytes > g.data()) return std::nullopt;
  }
  if (t.obj == 0 || t.obj > 0x3ffff) return std::nullopt;
  return t;
}

struct Header {
  std::uint32_t type = 0, parent = 0, mode = 0, uid = 0, gid = 0, mtime = 0, rdev = 0;
  std::uint64_t size = 0;
  std::int32_t equiv = 0;
  std::string name, alias;
};

std::optional<Header> header_of(std::span<const std::byte> d, bool be) {
  if (d.size() < 512) return std::nullopt;
  Header h;
  h.type = rd32(d.data(), be);
  if (h.type < kFile || h.type > kSpecial) return std::nullopt;
  h.parent = rd32(d.data() + 4, be);
  const char *name = reinterpret_cast<const char *>(d.data() + 10);
  const std::size_t nlen = strnlen(name, 256);
  if (nlen == 0 || nlen == 256) return std::nullopt;
  h.name.assign(name, nlen);
  h.mode = rd32(d.data() + 268, be);
  // The mode's file type agrees with the object's.
  const Kind k = mode_kind(h.mode);
  if ((h.type == kFile && k != Kind::file) || (h.type == kDirectory && k != Kind::directory) ||
      (h.type == kSymlink && k != Kind::symlink))
    return std::nullopt;
  if (h.parent == 0 || h.parent > 0x3ffff) return std::nullopt;
  h.uid = rd32(d.data() + 272, be);
  h.gid = rd32(d.data() + 276, be);
  h.mtime = rd32(d.data() + 284, be);
  h.size = rd32(d.data() + 292, be);
  const std::uint32_t high = rd32(d.data() + 496, be);
  if (high != 0xffffffffu) h.size |= std::uint64_t{high} << 32;
  h.equiv = static_cast<std::int32_t>(rd32(d.data() + 296, be));
  const char *alias = reinterpret_cast<const char *>(d.data() + 300);
  h.alias.assign(alias, strnlen(alias, 160));
  h.rdev = rd32(d.data() + 460, be);
  return h;
}

// How well the first chunks read with geometry g: valid headers count
// most; chunks that are neither tags nor erased count against.
long score(const Source &src, const Geometry &g) {
  const std::uint64_t n = std::min<std::uint64_t>(src.size() / g.stride(), 256);
  if (n == 0) return -1;
  long s = 0;
  long headers = 0;
  for (std::uint64_t i = 0; i < n; ++i) {
    const auto c = src.read_exact(i * g.stride(), g.stride(), "a YAFFS2 chunk");
    const std::size_t at = g.inband ? g.page - 16 : g.page + g.tag_off;
    bool erased = true;
    for (std::size_t k = at; k < at + 16; ++k) erased = erased && c[k] == std::byte{0xff};
    if (erased) continue;
    auto t = tags_of(c, g);
    if (!t) {
      s -= 4;
      continue;
    }
    if (t->header) {
      if (header_of(std::span(c).first(g.data()), g.be)) {
        s += 3;
        ++headers;
      } else {
        s -= 4;
      }
    } else {
      s += 1;
    }
  }
  return headers ? s : -1;
}

std::vector<Geometry> candidates() {
  static const std::pair<std::uint32_t, std::uint32_t> kSizes[] = {
      {2048, 64}, {4096, 128}, {4096, 224}, {4096, 256}, {8192, 256}, {8192, 448}, {8192, 640},
      {16384, 1280}, {512, 16}, {1024, 32}, {2048, 128}};
  std::vector<Geometry> out;
  for (bool be : {false, true}) {
    for (const auto &[page, spare] : kSizes)
      for (std::uint32_t off : {0u, 2u})
        if (off + 16 <= spare) out.push_back({page, spare, off, false, be});
    for (std::uint32_t page : {2048u, 4096u, 8192u, 16384u, 1024u, 512u}) out.push_back({page, 0, 0, true, be});
  }
  return out;
}

std::optional<Geometry> guess_geometry(const Source &src) {
  std::optional<Geometry> best;
  long best_score = 0;
  for (const Geometry &g : candidates()) {
    if (src.size() < g.stride()) continue;
    long s;
    try {
      s = score(src, g);
    } catch (const Error &) {
      continue;
    }
    if (s > best_score) {
      best_score = s;
      best = g;
    }
  }
  return best;
}

class Yaffs2 final : public FileSystem {
 public:
  Yaffs2(std::shared_ptr<const Source> src, Geometry g) : src_(std::move(src)), g_(g) {}

  void parse(const Context &ctx) {
    format_ = "yaffs2";
    WindowReader rd(*src_);
    const std::uint64_t nchunks = src_->size() / g_.stride();
    if (nchunks > kMaxChunks) throw LimitError("a YAFFS2 image of over 16 million chunks");
    struct Best {
      std::uint32_t seq = 0;
      std::uint64_t page = 0;
      std::uint32_t nbytes = 0;
    };
    std::unordered_map<std::uint32_t, Best> headers;
    std::uint64_t bad = 0;
    for (std::uint64_t i = 0; i < nchunks; ++i) {
      if ((i & 4095) == 0) ctx.check_cancelled();
      auto c = rd.get(i * g_.stride(), g_.stride());
      auto t = tags_of(c, g_);
      if (!t) continue;
      const Best b{t->seq, i, t->nbytes};
      auto keep = [&](Best &cur) {
        if (b.seq >= cur.seq) cur = b;  // the later page of a block wins a tie
      };
      if (t->header) {
        auto [it, fresh] = headers.try_emplace(t->obj, b);
        if (!fresh) keep(it->second);
      } else {
        auto [it, fresh] = chunks_[t->obj].try_emplace(t->chunk, Chunk{b.seq, b.page, b.nbytes});
        if (!fresh && b.seq >= it->second.seq) it->second = Chunk{b.seq, b.page, b.nbytes};
      }
    }
    std::unordered_map<std::uint32_t, Header> objs;
    for (const auto &[id, b] : headers) {
      const auto c = src_->read_exact(b.page * g_.stride(), g_.data(), "a YAFFS2 object header");
      auto h = header_of(c, g_.be);
      if (!h) {
        ++bad;
        continue;
      }
      objs[id] = std::move(*h);
    }
    if (objs.empty()) throw Error("no YAFFS2 object headers in the image");
    if (bad) warn(plural(bad, "object header doesn't parse and was", "object headers don't parse and were") + " skipped");
    std::map<std::uint32_t, std::vector<std::uint32_t>> children;
    for (const auto &[id, h] : objs)
      if (id != kRootId) children[h.parent].push_back(id);
    for (auto &[p, ids] : children) std::sort(ids.begin(), ids.end());
    TreeBuilder tree(*this, ctx.limits);
    std::set<std::uint32_t> seen{kRootId};
    std::vector<std::pair<std::uint32_t, std::uint32_t>> queue{{kRootId, 0}};
    // Objects put in lost+found (by the file system's own repair) show there.
    if (children.count(kLostFound) && !objs.count(kLostFound)) {
      Entry lf;
      lf.kind = Kind::directory;
      lf.name = "lost+found";
      queue.emplace_back(kLostFound, tree.add_child(0, std::move(lf)));
    }
    for (std::size_t q = 0; q < queue.size(); ++q) {
      ctx.check_cancelled();
      auto [dir, didx] = queue[q];
      auto it = children.find(dir);
      if (it == children.end()) continue;
      for (std::uint32_t id : it->second) {
        const Header &h = objs.at(id);
        if (h.name == "." || h.name == "..") continue;
        Entry e;
        e.name = h.name;
        e.mode = h.mode & 07777;
        e.has_mode = true;
        e.uid = h.uid;
        e.gid = h.gid;
        e.has_owner = true;
        e.mtime = h.mtime;
        e.has_mtime = true;
        e.loc0 = id;
        switch (h.type) {
          case kFile:
            e.kind = Kind::file;
            e.size = h.size;
            e.loc1 = h.size;
            break;
          case kSymlink:
            e.kind = Kind::symlink;
            e.link_target = h.alias;
            e.size = h.alias.size();
            break;
          case kDirectory: e.kind = Kind::directory; break;
          case kHardlink: {
            auto t = objs.find(static_cast<std::uint32_t>(h.equiv));
            if (t == objs.end() || t->second.type != kFile) {
              e.kind = Kind::other;
              e.note = "a hard link to object " + std::to_string(h.equiv) + ", which isn't a file in the image";
              break;
            }
            e.kind = Kind::file;
            e.loc0 = static_cast<std::uint32_t>(h.equiv);
            e.size = e.loc1 = t->second.size;
            e.mode = t->second.mode & 07777;
            e.note = "a hard link to " + display_name(t->second.name);
            break;
          }
          default: e.kind = mode_kind(h.mode); break;
        }
        if (e.kind == Kind::file) {
          auto c = chunks_.find(e.loc0);
          e.stored_size = c == chunks_.end() ? 0 : c->second.size() * std::uint64_t{g_.data()};
        }
        const bool d = e.kind == Kind::directory;
        const std::uint32_t idx = tree.add_child(didx, std::move(e));
        if (d) {
          if (!seen.insert(id).second) continue;
          queue.emplace_back(id, idx);
        }
      }
    }
    std::uint64_t dead = 0;
    for (const auto &[p, ids] : children)
      if (p == kUnlinked || p == kDeleted) dead += ids.size();
    tree.finish();
    description_ = "YAFFS2, " + std::to_string(g_.page) + "-byte pages " +
                   (g_.inband ? std::string("with inband tags")
                              : "+ " + std::to_string(g_.spare) + "-byte spare (tags at " + std::to_string(g_.tag_off) +
                                    ")") +
                   (g_.be ? ", big-endian" : "") + ", " + summary_counts(*this);
    if (dead) description_ += ", " + plural(dead, "deleted object", "deleted objects");
  }

  std::shared_ptr<Source> open(std::uint32_t entry, const Context &ctx) const override {
    const Entry &e = file_entry(entry);
    Sink sink(ctx);
    data(e.loc0, e.loc1, sink, ctx);
    return sink.finish();
  }

  std::vector<std::byte> head(std::uint32_t entry, std::uint64_t n, const Context &ctx) const override {
    const Entry &e = file_entry(entry);
    Sink sink(ctx, n);
    data(e.loc0, e.loc1, sink, ctx);
    return sink.finish()->head(n);
  }

 private:
  struct Chunk {
    std::uint32_t seq = 0;
    std::uint64_t page = 0;
    std::uint32_t nbytes = 0;
  };

  const Entry &file_entry(std::uint32_t entry) const {
    const Entry *e = &entries_.at(entry);
    if (e->kind == Kind::symlink) {
      auto t = resolve_link(entry);
      if (!t) throw Error("a link whose target isn't in the image");
      e = &entries_.at(*t);
    }
    if (e->kind != Kind::file) throw Error(display_name(e->name) + " is not a file");
    return *e;
  }

  void data(std::uint32_t obj, std::uint64_t size, Sink &sink, const Context &ctx) const {
    const std::uint32_t per = g_.data();
    const std::uint64_t n = (size + per - 1) / per;
    auto it = chunks_.find(obj);
    std::vector<std::byte> zeros(per);
    for (std::uint64_t k = 1; k <= n && !sink.full(); ++k) {
      if ((k & 255) == 0) ctx.check_cancelled();
      const std::size_t want = static_cast<std::size_t>(std::min<std::uint64_t>(per, size - (k - 1) * per));
      const Chunk *c = nullptr;
      if (it != chunks_.end() && k <= UINT32_MAX)
        if (auto f = it->second.find(static_cast<std::uint32_t>(k)); f != it->second.end()) c = &f->second;
      if (!c) {
        sink.append(std::span(zeros).first(want));
        continue;
      }
      auto b = src_->read_exact(c->page * g_.stride(), per, "a YAFFS2 data chunk");
      // Bytes past the chunk's count read as zeros.
      if (c->nbytes < per) std::fill(b.begin() + c->nbytes, b.end(), std::byte{0});
      sink.append(std::span(b).first(want));
    }
  }

  std::shared_ptr<const Source> src_;
  Geometry g_;
  std::unordered_map<std::uint32_t, std::map<std::uint32_t, Chunk>> chunks_;
};

}  // namespace

bool yaffs2_header(std::span<const std::byte> head) {
  // The first chunk is an object header at one of the geometries.
  for (const Geometry &g : candidates()) {
    if (head.size() < g.stride()) continue;
    auto t = tags_of(head.first(g.stride()), g);
    if (t && t->header && header_of(head.first(g.data()), g.be)) return true;
  }
  return false;
}

std::shared_ptr<FileSystem> open_yaffs2(std::shared_ptr<const Source> src, std::string_view, const Context &ctx) {
  auto g = guess_geometry(*src);
  if (!g) throw Error("no YAFFS2 page layout fits the image");
  auto fs = std::make_shared<Yaffs2>(std::move(src), *g);
  fs->parse(ctx);
  return fs;
}

}  // namespace revkit::container::detail
