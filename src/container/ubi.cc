// UBI images and the UBIFS file systems in their volumes (read-only;
// docs/filesystems.md).
//
// UBI: every physical erase block (PEB) starts with an erase-count header
// ("UBI#"), then a volume-ID header ("UBI!") saying which logical block
// (LEB) of which volume it holds, with a sequence number; the newest copy
// of a LEB wins. The PEB size is found from where the next erase-count
// header is. The layout volume holds the volume table (names, types,
// sizes). Each volume is a file of the container, its LEBs in order
// (unmapped ones read as zeros), and a UBIFS volume opens in turn.
//
// UBIFS: the superblock (LEB 0) gives the LEB size, the newest master node
// (LEBs 1 and 2) the root of the index, a B-tree whose leaves are inode,
// directory entry and data nodes. Data nodes are 4 KiB blocks, stored
// plainly or compressed with LZO, zlib (raw deflate) or zstd. Only what
// the index holds is read: a journal not yet committed is not replayed.
#include "formats.hh"

#include <array>
#include <algorithm>
#include <map>
#include <set>
#include <unordered_map>

namespace revkit::container::detail {
namespace {

// UBI's and UBIFS's CRC: CRC-32 seeded with 0xffffffff, no final inversion.
std::uint32_t ucrc(std::span<const std::byte> b) { return crc32_ieee(b, 0) ^ 0xffffffffu; }


std::string safe_name(std::string s) {
  for (char &c : s)
    if (c == '/' || static_cast<unsigned char>(c) < 0x20) c = '_';
  if (s.empty() || s == "." || s == "..") s = "_" + s;
  return s;
}

constexpr std::uint32_t kLayoutVolume = 0x7fffefff;

struct EcHeader {
  std::uint32_t vid_offset = 0, data_offset = 0, image_seq = 0;
};

std::optional<EcHeader> ec_header(std::span<const std::byte> b) {
  if (b.size() < 64 || be32(b.data()) != 0x55424923u) return std::nullopt;
  if (ucrc(b.first(60)) != be32(b.data() + 60)) return std::nullopt;
  EcHeader h;
  h.vid_offset = be32(b.data() + 16);
  h.data_offset = be32(b.data() + 20);
  h.image_seq = be32(b.data() + 24);
  return h;
}

class Ubi final : public FileSystem {
 public:
  explicit Ubi(std::shared_ptr<const Source> src) : src_(std::move(src)) {}

  void parse(const Context &ctx) {
    format_ = "ubi";
    WindowReader rd(*src_);
    const std::uint64_t size = src_->size();
    auto first = ec_header(rd.get(0, 64));
    if (!first) throw Error("not a UBI image (no erase-count header at its start)");
    if (first->vid_offset < 64 || first->data_offset <= first->vid_offset || first->data_offset % 8)
      throw Error("a UBI erase-count header with impossible offsets");
    // The PEB size: where the next erase-count header is.
    std::uint64_t peb = 0;
    for (std::uint64_t c = 4096; c <= (16u << 20); c <<= 1) {
      if (c <= first->data_offset) continue;
      if (c >= size) break;
      if (ec_header(rd.get(c, 64))) {
        peb = c;
        break;
      }
    }
    if (!peb) peb = size;  // a single PEB
    if (peb <= first->data_offset) throw Error("a UBI image shorter than one erase block");
    peb_ = peb;
    leb_ = peb - first->data_offset;
    struct Leb {
      std::uint64_t sqnum = 0, phys = 0;
      std::uint32_t data_size = 0;
    };
    struct Vol {
      std::map<std::uint32_t, Leb> lebs;
      std::uint8_t type = 0;
      std::uint32_t used_ebs = 0, data_pad = 0;
    };
    std::map<std::uint32_t, Vol> vols;
    const std::uint64_t pebs = size / peb;
    if (pebs > (1u << 22)) throw LimitError("a UBI image of over 4 million erase blocks");
    std::uint64_t foreign = 0, empty = 0, bad = 0;
    for (std::uint64_t i = 0; i < pebs; ++i) {
      if ((i & 255) == 0) ctx.check_cancelled();
      const std::uint64_t base = i * peb;
      auto ec = ec_header(rd.get(base, 64));
      if (!ec) {
        ++bad;
        continue;
      }
      if (ec->image_seq != first->image_seq && ec->image_seq && first->image_seq) {
        ++foreign;
        continue;
      }
      if (ec->vid_offset + 64ull > peb || ec->data_offset >= peb) {
        ++bad;
        continue;
      }
      auto v = rd.get(base + ec->vid_offset, 64);
      if (v.size() < 64 || be32(v.data()) != 0x55424921u) {
        ++empty;  // erased: no volume data
        continue;
      }
      if (ucrc(v.first(60)) != be32(v.data() + 60)) {
        ++bad;
        continue;
      }
      const std::uint32_t vol_id = be32(v.data() + 8), lnum = be32(v.data() + 12);
      Vol &vol = vols[vol_id];
      vol.type = static_cast<std::uint8_t>(v[5]);
      vol.used_ebs = std::max(vol.used_ebs, be32(v.data() + 24));
      vol.data_pad = be32(v.data() + 28);
      Leb l{be64(v.data() + 40), base + ec->data_offset, be32(v.data() + 20)};
      auto [it, fresh] = vol.lebs.try_emplace(lnum, l);
      if (!fresh && l.sqnum > it->second.sqnum) it->second = l;
    }
    if (vols.empty()) throw Error("a UBI image with no volumes");
    if (foreign) warn(plural(foreign, "erase block belongs", "erase blocks belong") + " to another UBI image and " +
                      (foreign == 1 ? "was" : "were") + " skipped");
    if (bad) warn(plural(bad, "erase block has", "erase blocks have") + " a damaged header");
    // The volume table.
    struct Rec {
      std::string name;
      std::uint32_t reserved = 0, data_pad = 0;
      std::uint8_t type = 0;
      bool autoresize = false;
    };
    std::map<std::uint32_t, Rec> table;
    if (auto lay = vols.find(kLayoutVolume); lay != vols.end() && lay->second.lebs.count(0)) {
      const Leb &l = lay->second.lebs.at(0);
      const std::uint64_t n = std::min<std::uint64_t>(128, leb_ / 172);
      const auto t = src_->read_exact(l.phys, n * 172, "the UBI volume table");
      for (std::uint64_t r = 0; r < n; ++r) {
        const std::byte *p = t.data() + r * 172;
        if (be32(p) == 0) continue;
        if (ucrc(std::span(p, 168)) != be32(p + 168)) {
          warn("volume table record " + std::to_string(r) + " fails its CRC");
          continue;
        }
        Rec rec;
        rec.reserved = be32(p);
        rec.data_pad = be32(p + 8);
        rec.type = static_cast<std::uint8_t>(p[12]);
        const std::uint16_t nlen = std::min<std::uint16_t>(be16(p + 14), 127);
        rec.name.assign(reinterpret_cast<const char *>(p + 16), nlen);
        rec.autoresize = (static_cast<std::uint8_t>(p[144]) & 1) != 0;
        table[static_cast<std::uint32_t>(r)] = rec;
      }
    } else {
      warn("no volume table: volumes are named by number");
    }
    TreeBuilder tree(*this, ctx.limits);
    std::set<std::string> names;
    for (auto &[id, vol] : vols) {
      if (id == kLayoutVolume) continue;
      const Rec *rec = table.count(id) ? &table.at(id) : nullptr;
      const std::uint32_t pad = rec ? rec->data_pad : vol.data_pad;
      if (pad >= leb_) continue;
      const std::uint64_t usable = leb_ - pad;
      const bool is_static = (rec ? rec->type : vol.type) == 2;
      std::vector<Run> runs;
      std::uint64_t vsize = 0;
      for (const auto &[lnum, l] : vol.lebs) {
        std::uint64_t len = usable;
        if (is_static) {
          if (lnum >= vol.used_ebs) continue;
          len = std::min<std::uint64_t>(l.data_size, usable);
        }
        if (l.phys + len > size) continue;
        runs.push_back({lnum * usable, l.phys, len, false});
        vsize = std::max(vsize, lnum * usable + len);
      }
      Entry e;
      e.kind = Kind::file;
      std::string name = rec && !rec->name.empty() ? safe_name(rec->name) : "vol" + std::to_string(id);
      if (!names.insert(name).second) name += "~" + std::to_string(id);
      e.name = name;
      e.size = vsize;
      e.stored_size = runs.size() * peb_;
      e.loc0 = volumes_.size();
      e.note = std::string(is_static ? "static" : "dynamic") + " volume " + std::to_string(id) + ", " +
               plural(vol.lebs.size(), "LEB", "LEBs") + " of " + std::to_string(usable) + " bytes" +
               (rec ? ", " + std::to_string(rec->reserved) + " reserved" : "") +
               (rec && rec->autoresize ? ", autoresize" : "");
      volumes_.push_back({std::move(runs), vsize});
      tree.add_child(0, std::move(e));
    }
    tree.finish();
    description_ = "UBI image, " + plural(entries_.size() - 1, "volume", "volumes") + ", erase blocks of " +
                   std::to_string(peb_ / 1024) + " KiB (LEBs of " + std::to_string(leb_) + " bytes)";
    if (empty) description_ += ", " + plural(empty, "free erase block", "free erase blocks");
  }

  std::shared_ptr<Source> open(std::uint32_t entry, const Context &) const override {
    const Entry &e = entries_.at(entry);
    if (e.kind != Kind::file) throw Error("not a file");
    const Volume &v = volumes_.at(e.loc0);
    return mapped_source(src_, v.runs, v.size);
  }
  bool stored_plain(std::uint32_t) const override { return true; }

 private:
  struct Volume {
    std::vector<Run> runs;
    std::uint64_t size = 0;
  };
  std::shared_ptr<const Source> src_;
  std::uint64_t peb_ = 0, leb_ = 0;
  std::vector<Volume> volumes_;
};

// ---- UBIFS -----------------------------------------------------------------------

constexpr std::uint32_t kUbifsMagic = 0x06101831;
enum : std::uint8_t { kIno = 0, kData = 1, kDent = 2, kXent = 3, kSb = 6, kMst = 7, kIdx = 9 };
constexpr std::uint32_t kBlock = 4096;
constexpr std::size_t kMaxNodes = 16u << 20;

Kind itype_kind(std::uint8_t t) {
  switch (t) {
    case 0: return Kind::file;
    case 1: return Kind::directory;
    case 2: return Kind::symlink;
    case 3: return Kind::block_device;
    case 4: return Kind::char_device;
    case 5: return Kind::fifo;
    case 6: return Kind::socket;
    default: return Kind::other;
  }
}

class Ubifs final : public FileSystem {
 public:
  explicit Ubifs(std::shared_ptr<const Source> src) : src_(std::move(src)) {}

  void parse(const Context &ctx) {
    format_ = "ubifs";
    const auto sbb = src_->read_exact(0, 4096 < src_->size() ? 4096 : src_->size(), "the UBIFS superblock");
    const auto sb = node_at(sbb, 0);
    if (!sb || sb->type != kSb || sb->len < 160) throw Error("not a UBIFS image (no superblock node)");
    Buf b(sbb, "the UBIFS superblock");
    const std::uint8_t key_fmt = b.u8(27);
    const std::uint32_t flags = b.l32(28);
    min_io_ = b.l32(32);
    leb_ = b.l32(36);
    const std::uint32_t leb_cnt = b.l32(40);
    const std::uint32_t fmt = b.l32(80);
    const std::uint16_t compr = b.l16(84);
    if (leb_ < 4096 || leb_ > (64u << 20) || min_io_ == 0 || min_io_ > leb_)
      throw Error("a UBIFS superblock with an impossible LEB size");
    if (key_fmt != 0) throw Error("UBIFS key format " + std::to_string(key_fmt) + " is not supported");
    if (flags & 0x20) throw Error("an authenticated UBIFS (its index carries hashes) is not supported");
    // The newest master node in LEBs 1 and 2.
    std::optional<std::uint64_t> best_sq;
    std::vector<std::byte> mst;
    for (std::uint64_t lnum : {1u, 2u}) {
      if ((lnum + 1) * leb_ > src_->size()) break;
      const auto l = src_->read_exact(lnum * leb_, leb_, "a UBIFS master area");
      for (std::size_t off = 0; off + 24 <= l.size(); off += 8) {
        if (le32(l.data() + off) != kUbifsMagic) continue;
        auto n = node_at(l, off);
        if (!n) continue;
        if (n->type == kMst && n->len >= 80 && (!best_sq || n->sqnum > *best_sq)) {
          best_sq = n->sqnum;
          mst.assign(l.begin() + static_cast<std::ptrdiff_t>(off), l.begin() + static_cast<std::ptrdiff_t>(off + n->len));
        }
        off += ((n->len + 7u) & ~7u) - 8;
      }
    }
    if (mst.empty()) throw Error("a UBIFS image with no master node");
    Buf m(mst, "the UBIFS master node");
    const std::uint32_t root_lnum = m.l32(48), root_offs = m.l32(52);
    // The index.
    walk_index(root_lnum, root_offs, 0, ctx);
    TreeBuilder tree(*this, ctx.limits);
    if (auto r = inodes_.find(1); r != inodes_.end()) {
      entries_[0].mode = r->second.mode & 07777;
      entries_[0].has_mode = true;
      entries_[0].mtime = r->second.mtime;
      entries_[0].has_mtime = true;
    }
    std::set<std::uint64_t> seen{1};
    std::vector<std::pair<std::uint64_t, std::uint32_t>> queue{{1, 0}};
    for (std::size_t q = 0; q < queue.size(); ++q) {
      ctx.check_cancelled();
      auto [dino, didx] = queue[q];
      auto it = dents_.find(dino);
      if (it == dents_.end()) continue;
      for (const Dent &d : it->second) {
        if (d.name.empty() || d.name == "." || d.name == "..") continue;
        Entry e;
        e.name = d.name;
        const Inode *ino = inodes_.count(d.inum) ? &inodes_.at(d.inum) : nullptr;
        e.kind = ino ? mode_kind(ino->mode) : itype_kind(d.type);
        if (ino) {
          e.mode = ino->mode & 07777;
          e.has_mode = true;
          e.uid = ino->uid;
          e.gid = ino->gid;
          e.has_owner = true;
          e.mtime = ino->mtime;
          e.has_mtime = true;
        }
        e.loc0 = d.inum;
        if (e.kind == Kind::file) {
          e.size = ino ? ino->size : 0;
          if (ino && ino->encrypted) {
            e.note = "encrypted (fscrypt)";
            e.loc2 = UINT64_MAX;
          }
          if (auto b2 = blocks_.find(d.inum); b2 != blocks_.end())
            for (const auto &[n, blk] : b2->second) e.stored_size += blk.len;
        } else if (e.kind == Kind::symlink && ino) {
          e.link_target = ino->target;
          e.size = ino->target.size();
        }
        const bool dir = e.kind == Kind::directory;
        const std::uint32_t idx = tree.add_child(didx, std::move(e));
        if (dir) {
          if (!seen.insert(d.inum).second) {
            warn("directory inode " + std::to_string(d.inum) + " is listed twice: its second listing is empty");
            continue;
          }
          queue.emplace_back(d.inum, idx);
        }
      }
    }
    tree.finish();
    static const char *names[] = {"none", "lzo", "zlib", "zstd"};
    description_ = "UBIFS (format " + std::to_string(fmt) + "), " + (compr < 4 ? names[compr] : "compression ?") +
                   ", " + plural(leb_cnt, "LEB", "LEBs") + " of " + std::to_string(leb_) + " bytes, " +
                   summary_counts(*this);
  }

  std::shared_ptr<Source> open(std::uint32_t entry, const Context &ctx) const override {
    const Entry &e = file_entry(entry);
    Sink sink(ctx);
    data(e.loc0, e.size, sink, ctx);
    return sink.finish();
  }

  std::vector<std::byte> head(std::uint32_t entry, std::uint64_t n, const Context &ctx) const override {
    const Entry &e = file_entry(entry);
    Sink sink(ctx, n);
    data(e.loc0, e.size, sink, ctx);
    return sink.finish()->head(n);
  }

 private:
  struct Node {
    std::uint8_t type = 0;
    std::uint32_t len = 0;
    std::uint64_t sqnum = 0;
  };
  struct Inode {
    std::uint64_t size = 0;
    std::uint32_t mode = 0, uid = 0, gid = 0;
    std::int64_t mtime = 0;
    std::string target;
    bool encrypted = false;
  };
  struct Dent {
    std::string name;
    std::uint64_t inum = 0;
    std::uint8_t type = 0;
  };
  struct Block {
    std::uint64_t pos = 0;
    std::uint32_t len = 0;
  };

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

  // A node's header at `off` of a buffer, its CRC checked.
  static std::optional<Node> node_at(std::span<const std::byte> b, std::size_t off) {
    if (off + 24 > b.size() || le32(b.data() + off) != kUbifsMagic) return std::nullopt;
    Node n;
    n.sqnum = le64(b.data() + off + 8);
    n.len = le32(b.data() + off + 16);
    n.type = static_cast<std::uint8_t>(b[off + 20]);
    if (n.len < 24 || n.len > b.size() - off) return std::nullopt;
    if (ucrc(b.subspan(off + 8, n.len - 8)) != le32(b.data() + off + 4)) return std::nullopt;
    return n;
  }

  // The node at (lnum, offs), read whole, CRC checked.
  std::vector<std::byte> read_node(std::uint32_t lnum, std::uint32_t offs, std::uint32_t len_hint, Node &n) const {
    if (offs >= leb_) throw Error("a UBIFS node reference outside its LEB");
    const std::uint64_t pos = std::uint64_t{lnum} * leb_ + offs;
    const auto h = src_->read_exact(pos, 24, "a UBIFS node");
    if (le32(h.data()) != kUbifsMagic) throw Error("a UBIFS node reference to no node");
    const std::uint32_t len = le32(h.data() + 16);
    if (len < 24 || len > leb_ - offs || (len_hint && len != len_hint)) throw Error("a UBIFS node of a wrong length");
    auto b = src_->read_exact(pos, len, "a UBIFS node");
    auto ok = node_at(b, 0);
    if (!ok) throw Error("a UBIFS node fails its CRC");
    n = *ok;
    return b;
  }

  void walk_index(std::uint32_t lnum, std::uint32_t offs, unsigned depth, const Context &ctx) {
    if (depth > 64) throw Error("the UBIFS index is too deep");
    if (!visited_.insert(std::uint64_t{lnum} * leb_ + offs).second) throw Error("the UBIFS index loops");
    ctx.check_cancelled();
    // The branches are copied out and the node's buffer released before
    // the walk goes down: 64 levels of LEB-sized buffers aren't held at once
    // (bug scrub part 3).
    std::vector<std::array<std::uint32_t, 3>> branches;
    std::uint16_t level = 0;
    {
      Node n;
      const auto b = read_node(lnum, offs, 0, n);
      if (n.type != kIdx) throw Error("a UBIFS index reference to a node of type " + std::to_string(n.type));
      Buf ib(b, "a UBIFS index node");
      const std::uint16_t count = ib.l16(24);
      level = ib.l16(26);
      constexpr std::size_t kBranch = 12 + 8;
      branches.reserve(count);
      for (std::uint16_t i = 0; i < count; ++i) {
        const std::size_t at = 28 + i * kBranch;
        branches.push_back({ib.l32(at), ib.l32(at + 4), ib.l32(at + 8)});
      }
    }
    for (const auto &[cl, co, clen] : branches) {
      if (level > 0) {
        walk_index(cl, co, depth + 1, ctx);
      } else {
        if (++leaves_ > kMaxNodes) throw LimitError("a UBIFS index of over 16 million nodes");
        // Index nodes may all point at one leaf, a long name or a large
        // node, each read again: a leaf is read once, and what leaves read
        // is budgeted at four times the image (bug scrub part 3).
        if ((leaves_ & 1023) == 0) ctx.check_cancelled();
        if (!leaf_seen_.insert(std::uint64_t{cl} * leb_ + co).second) continue;
        leaf_bytes_ += clen;
        if (leaf_bytes_ > 4 * src_->size() + (64u << 20))
          throw LimitError("the UBIFS index's leaves read more than four times the image");
        try {
          leaf(cl, co, clen);
        } catch (const LimitError &) {
          throw;
        } catch (const Error &err) {
          if (++bad_leaves_ == 1) warn(std::string("unreadable UBIFS nodes: ") + err.what());
        }
      }
    }
  }

  void leaf(std::uint32_t lnum, std::uint32_t offs, std::uint32_t len) {
    if (len < 24 || offs >= leb_ || len > leb_ - offs) throw Error("a UBIFS index branch out of range");
    const std::uint64_t pos = std::uint64_t{lnum} * leb_ + offs;
    // Data nodes are read when their file is: only the header now.
    const auto h = src_->read_exact(pos, std::min<std::uint32_t>(len, 160), "a UBIFS node");
    if (le32(h.data()) != kUbifsMagic) throw Error("an index branch to no node");
    const std::uint8_t type = static_cast<std::uint8_t>(h[20]);
    Buf nb(h, "a UBIFS node");
    const std::uint32_t inum = nb.l32(24);
    if (type == kData) {
      const std::uint32_t block = nb.l32(28) & 0x1fffffffu;
      blocks_[inum][block] = Block{pos, len};
      return;
    }
    Node n;
    const auto b = read_node(lnum, offs, len, n);
    Buf full(b, "a UBIFS node");
    if (type == kIno) {
      if (b.size() < 160) throw Error("a short UBIFS inode node");
      Inode i;
      i.size = full.l64(48);
      i.mtime = static_cast<std::int64_t>(full.l64(72));
      i.uid = full.l32(96);
      i.gid = full.l32(100);
      i.mode = full.l32(104);
      i.encrypted = (full.l32(108) & 0x40) != 0;
      const std::uint32_t dlen = full.l32(112);
      if (mode_kind(i.mode) == Kind::symlink && dlen <= b.size() - 160 && dlen <= 4096)
        i.target.assign(reinterpret_cast<const char *>(b.data() + 160), dlen);
      inodes_[inum] = std::move(i);
    } else if (type == kDent) {
      const std::uint16_t nlen = full.l16(50);
      if (56u + nlen > b.size()) throw Error("a UBIFS directory entry runs past its node");
      Dent d;
      d.inum = full.l64(40);
      d.type = full.u8(49);
      d.name.assign(reinterpret_cast<const char *>(b.data() + 56), nlen);
      if (d.inum) dents_[inum].push_back(std::move(d));
    }
  }

  void data(std::uint64_t inum, std::uint64_t size, Sink &sink, const Context &ctx) const {
    static const std::vector<std::byte> zeros(kBlock);
    auto it = blocks_.find(inum);
    const std::uint64_t nblocks = (size + kBlock - 1) / kBlock;
    std::vector<std::byte> out(kBlock);
    for (std::uint64_t k = 0; k < nblocks && !sink.full(); ++k) {
      if ((k & 63) == 0) ctx.check_cancelled();
      const std::size_t want = static_cast<std::size_t>(std::min<std::uint64_t>(kBlock, size - k * kBlock));
      const Block *blk = nullptr;
      if (it != blocks_.end())
        if (auto b = it->second.find(static_cast<std::uint32_t>(k)); b != it->second.end()) blk = &b->second;
      if (!blk) {
        sink.append(std::span(zeros).first(want));
        continue;
      }
      const auto raw = src_->read_exact(blk->pos, blk->len, "a UBIFS data node");
      if (!node_at(raw, 0)) throw Error("a UBIFS data node fails its CRC");
      Buf nb(raw, "a UBIFS data node");
      const std::uint32_t dsize = nb.l32(40);
      const std::uint16_t compr = nb.l16(44);
      const auto in = std::span(raw).subspan(48);
      if (dsize > kBlock) throw Error("a UBIFS data node over 4 KiB");
      std::fill(out.begin(), out.end(), std::byte{0});
      std::size_t got = 0;
      switch (compr) {
        case 0:
          if (in.size() < dsize) throw Error("a short UBIFS data node");
          std::memcpy(out.data(), in.data(), dsize);
          got = dsize;
          break;
        case 1: got = decompress_block(Codec::lzo1x, in, std::span(out).first(dsize)); break;
        case 2: got = decompress_block(Codec::deflate, in, std::span(out).first(dsize)); break;
        case 3: got = decompress_block(Codec::zstd, in, std::span(out).first(dsize)); break;
        default: throw Error("UBIFS compression " + std::to_string(compr) + " is not known");
      }
      if (got != dsize) throw Error("a UBIFS data node decodes short");
      sink.append(std::span(out).first(want));
    }
  }

  std::shared_ptr<const Source> src_;
  std::uint32_t leb_ = 0, min_io_ = 0;
  std::set<std::uint64_t> visited_, leaf_seen_;
  std::uint64_t leaves_ = 0, bad_leaves_ = 0, leaf_bytes_ = 0;
  std::unordered_map<std::uint64_t, Inode> inodes_;
  std::map<std::uint64_t, std::vector<Dent>> dents_;
  std::unordered_map<std::uint64_t, std::map<std::uint32_t, Block>> blocks_;
};

}  // namespace

bool ubi_header(std::span<const std::byte> b) { return ec_header(b).has_value(); }

bool ubifs_header(std::span<const std::byte> b) {
  if (b.size() < 24 || le32(b.data()) != kUbifsMagic || static_cast<std::uint8_t>(b[20]) != kSb) return false;
  const std::uint32_t len = le32(b.data() + 16);
  return len >= 160 && len <= b.size() && ucrc(b.subspan(8, len - 8)) == le32(b.data() + 4);
}

std::shared_ptr<FileSystem> open_ubi(std::shared_ptr<const Source> src, std::string_view, const Context &ctx) {
  auto fs = std::make_shared<Ubi>(std::move(src));
  fs->parse(ctx);
  return fs;
}

std::shared_ptr<FileSystem> open_ubifs(std::shared_ptr<const Source> src, std::string_view, const Context &ctx) {
  auto fs = std::make_shared<Ubifs>(std::move(src));
  fs->parse(ctx);
  return fs;
}

}  // namespace revkit::container::detail
