// ext2, ext3 and ext4, read-only: the superblock, group descriptors (32-
// and 64-bit, meta_bg), inodes, extent trees and the old block maps (holes
// read as zeros), inline data, fast and slow symlinks, and directories
// read linearly (hashed directories are linear to a reader). The journal
// is not replayed: an image that needs recovery is read as it is, with a
// warning. Files map onto the image's blocks without a copy.
#include "formats.hh"

#include <functional>
#include <set>

namespace revkit::container::detail {
namespace {

constexpr std::uint32_t kExtents = 0x80000, kInline = 0x10000000, kEncrypt = 0x800;
constexpr std::uint32_t kIncompatFiletype = 0x2, kIncompatRecover = 0x4, kIncompatMetaBg = 0x10,
                        kIncompat64 = 0x80, kIncompatInline = 0x8000, kIncompatEncrypt = 0x10000;
constexpr std::uint32_t kRoSparse = 0x1;

Kind kind_of_mode(std::uint32_t mode) {
  switch (mode & 0170000) {
    case 0100000: return Kind::file;
    case 0040000: return Kind::directory;
    case 0120000: return Kind::symlink;
    case 0020000: return Kind::char_device;
    case 0060000: return Kind::block_device;
    case 0010000: return Kind::fifo;
    case 0140000: return Kind::socket;
    default: return Kind::other;
  }
}

bool power_of(std::uint64_t n, std::uint64_t base) {
  if (n == 0) return false;
  while (n % base == 0) n /= base;
  return n == 1;
}

class Ext final : public FileSystem {
 public:
  explicit Ext(std::shared_ptr<const Source> src) : src_(std::move(src)) {}

  void parse(const Context &ctx) {
    format_ = "ext";
    const auto sbb = src_->read_exact(1024, 1024, "the ext superblock");
    Buf sb(sbb, "the ext superblock");
    if (sb.l16(0x38) != 0xef53) throw Error("not an ext file system");
    const std::uint32_t log = sb.l32(0x18);
    if (log > 6) throw Error("an ext block size past 64 KiB");
    bs_ = 1024u << log;
    inodes_count_ = sb.l32(0x00);
    first_data_ = sb.l32(0x14);
    bpg_ = sb.l32(0x20);
    ipg_ = sb.l32(0x28);
    const std::uint32_t rev = sb.l32(0x4c);
    isize_ = rev >= 1 ? sb.l16(0x58) : 128;
    incompat_ = sb.l32(0x60);
    const std::uint32_t ro = sb.l32(0x64);
    sparse_ = ro & kRoSparse;
    desc_size_ = (incompat_ & kIncompat64) ? std::max<std::uint16_t>(sb.l16(0xfe), 32) : 32;
    first_meta_bg_ = sb.l32(0x104);
    std::uint64_t blocks = sb.l32(0x04);
    if (incompat_ & kIncompat64) blocks |= static_cast<std::uint64_t>(sb.l32(0x150)) << 32;
    if (bpg_ == 0 || ipg_ == 0 || isize_ < 128 || isize_ > bs_ || (isize_ & (isize_ - 1)) || desc_size_ > 1024)
      throw Error("ext superblock geometry is invalid");
    groups_ = static_cast<std::uint32_t>((blocks - first_data_ + bpg_ - 1) / bpg_);
    if (groups_ == 0 || static_cast<std::uint64_t>(groups_) * ipg_ < inodes_count_ / 2)
      throw Error("ext group count is inconsistent");
    if (static_cast<std::uint64_t>(blocks) * bs_ > src_->size() + bs_)
      warn("the image is shorter than its file system (" + std::to_string(blocks * bs_) + " bytes)");
    if (incompat_ & kIncompatRecover)
      warn("the journal holds changes not replayed: the newest writes may be missing");
    const char *name = (incompat_ & 0x40) ? "ext4" : (sb.l32(0x5c) & 0x4) ? "ext3" : "ext2";
    TreeBuilder tree(*this, ctx.limits);
    std::set<std::uint32_t> seen;
    const Inode root = inode(2);
    if (kind_of_mode(root.mode) != Kind::directory) throw Error("the ext root is not a directory");
    entries_[0].mode = root.mode & 07777;
    entries_[0].has_mode = true;
    entries_[0].mtime = root.mtime;
    entries_[0].has_mtime = true;
    walk(tree, 0, 2, root, seen, ctx, 0);
    tree.finish();
    description_ = std::string(name) + " file system, " + summary_counts(*this);
  }

  std::shared_ptr<Source> open(std::uint32_t entry, const Context &) const override {
    const Entry *e = &entries_.at(entry);
    if (e->kind == Kind::symlink || e->kind == Kind::hardlink) {
      auto t = resolve_link(entry);
      if (!t) throw Error("a link whose target isn't in the image");
      e = &entries_.at(*t);
    }
    if (e->kind != Kind::file) throw Error(display_name(e->name) + " is not a file");
    if (e->loc2 == UINT64_MAX) throw Error(display_name(e->name) + ": " + e->note);
    return content(inode(static_cast<std::uint32_t>(e->loc0)));
  }

 private:
  struct Inode {
    std::uint32_t mode = 0, uid = 0, gid = 0, flags = 0;
    std::int64_t mtime = 0;
    std::uint64_t size = 0;
    std::vector<std::byte> raw;  // the whole on-disk inode
  };

  bool has_super(std::uint32_t g) const {
    if (!sparse_) return true;
    return g == 0 || g == 1 || power_of(g, 3) || power_of(g, 5) || power_of(g, 7);
  }

  std::uint64_t inode_table(std::uint32_t g) const {
    const std::uint32_t per_block = bs_ / desc_size_;
    std::uint64_t at;
    if ((incompat_ & kIncompatMetaBg) && g / per_block >= first_meta_bg_) {
      const std::uint32_t first = g / per_block * per_block;
      const std::uint64_t block = first_data_ + static_cast<std::uint64_t>(first) * bpg_ + (has_super(first) ? 1 : 0);
      at = block * bs_ + static_cast<std::uint64_t>(g % per_block) * desc_size_;
    } else {
      at = static_cast<std::uint64_t>(first_data_ + 1) * bs_ + static_cast<std::uint64_t>(g) * desc_size_;
    }
    const auto d = src_->read_exact(at, desc_size_, "an ext group descriptor");
    std::uint64_t t = le32(d.data() + 0x08);
    if (desc_size_ >= 64) t |= static_cast<std::uint64_t>(le32(d.data() + 0x28)) << 32;
    return t;
  }

  Inode inode(std::uint32_t ino) const {
    if (ino == 0 || ino > static_cast<std::uint64_t>(groups_) * ipg_) throw Error("an ext inode number out of range");
    const std::uint32_t g = (ino - 1) / ipg_, i = (ino - 1) % ipg_;
    const std::uint64_t at = inode_table(g) * bs_ + static_cast<std::uint64_t>(i) * isize_;
    Inode n;
    n.raw = src_->read_exact(at, isize_, "an ext inode");
    Buf b(n.raw, "an ext inode");
    n.mode = b.l16(0x00);
    n.uid = b.l16(0x02) | static_cast<std::uint32_t>(b.l16(0x78)) << 16;
    n.gid = b.l16(0x18) | static_cast<std::uint32_t>(b.l16(0x7a)) << 16;
    n.size = b.l32(0x04) | static_cast<std::uint64_t>(b.l32(0x6c)) << 32;
    n.mtime = b.l32(0x10);
    n.flags = b.l32(0x20);
    return n;
  }

  // The file's blocks as runs (offsets in bytes).
  // How many blocks the image holds: a file's extent tree nodes, indirect
  // blocks and data blocks are distinct blocks of it, so none can number
  // more. That bounds the time a crafted tree or block map of repeated
  // blocks takes (2^20 visits of 4 KiB each, or 2^22 indirect blocks of
  // 1,024 entries each, took tens of seconds per open), as the caps alone
  // bounded only the memory.
  std::uint64_t image_blocks() const { return src_->size() / bs_ + 16; }

  void extents(std::span<const std::byte> node, std::vector<Run> &runs, unsigned depth, std::uint32_t &visits,
               std::uint64_t &mapped) const {
    if (++visits > std::min<std::uint64_t>(1u << 20, image_blocks()))
      throw LimitError("an ext extent tree is too large (it repeats its blocks)");
    Buf b(node, "an ext extent node");
    if (b.l16(0) != 0xf30a) throw Error("a bad ext extent header");
    const std::uint16_t count = b.l16(2), d = b.l16(6);
    if (d > 5 || (depth && d >= depth)) throw Error("an ext extent tree too deep");
    if (12u + 12u * count > node.size()) throw Error("an ext extent node overflows");
    for (std::uint16_t k = 0; k < count; ++k) {
      const std::size_t o = 12u + 12u * k;
      if (d == 0) {
        const std::uint64_t logical = b.l32(o);
        std::uint32_t len = b.l16(o + 4);
        bool zero = false;
        if (len > 32768) {
          len -= 32768;  // unwritten: reads as zeros
          zero = true;
        }
        const std::uint64_t phys = static_cast<std::uint64_t>(b.l16(o + 6)) << 32 | b.l32(o + 8);
        runs.push_back({logical * bs_, phys * bs_, static_cast<std::uint64_t>(len) * bs_, zero});
        if (runs.size() > (1u << 22)) throw LimitError("an ext file with too many extents");
        if (!zero && (mapped += len) > image_blocks())
          throw LimitError("an ext file maps more blocks than the image has");
      } else {
        const std::uint64_t leaf = static_cast<std::uint64_t>(b.l16(o + 8)) << 32 | b.l32(o + 4);
        const auto child = src_->read_exact(leaf * bs_, bs_, "an ext extent block");
        extents(child, runs, d, visits, mapped);
      }
    }
  }

  // The old block map: 12 direct, then single, double, triple indirect.
  void blockmap(const Inode &n, std::vector<Run> &runs) const {
    const std::uint64_t per = bs_ / 4;
    const std::uint64_t nblocks = (n.size + bs_ - 1) / bs_;
    std::uint64_t logical = 0;
    std::uint32_t reads = 0;
    std::uint64_t mapped = 0;
    auto add = [&](std::uint64_t phys) {
      if (phys) {
        if (++mapped > image_blocks()) throw LimitError("an ext file maps more blocks than the image has");
        if (!runs.empty() && !runs.back().zero && runs.back().logical + runs.back().length == logical * bs_ &&
            runs.back().physical + runs.back().length == phys * bs_)
          runs.back().length += bs_;
        else
          runs.push_back({logical * bs_, phys * bs_, bs_, false});
        // As for extents: indirect blocks repeating one non-contiguous
        // block made a Run per block, 2^28 from one double-indirect block.
        if (runs.size() > (1u << 22)) throw LimitError("an ext file with too many blocks");
      }
      ++logical;
    };
    std::function<void(std::uint64_t, int)> indirect = [&](std::uint64_t block, int level) {
      if (logical >= nblocks) return;
      if (block == 0) {
        std::uint64_t span = 1;
        for (int k = 0; k < level; ++k) span *= per;
        logical += span;  // a hole the size of the whole subtree
        return;
      }
      if (++reads > std::min<std::uint64_t>(1u << 22, image_blocks()))
        throw LimitError("an ext block map too large (it repeats its blocks)");
      const auto t = src_->read_exact(block * bs_, bs_, "an ext indirect block");
      for (std::uint64_t k = 0; k < per && logical < nblocks; ++k) {
        const std::uint32_t b = le32(t.data() + 4 * k);
        if (level == 1)
          add(b);
        else
          indirect(b, level - 1);
      }
    };
    Buf b(n.raw, "an ext inode");
    for (int k = 0; k < 12 && logical < nblocks; ++k) add(b.l32(0x28 + 4 * k));
    for (int level = 1; level <= 3 && logical < nblocks; ++level) indirect(b.l32(0x28 + 4 * (11 + level)), level);
  }

  // Inline data: i_block's 60 bytes, then the "system.data" attribute.
  std::vector<std::byte> inline_data(const Inode &n) const {
    Buf b(n.raw, "an ext inode");
    std::vector<std::byte> out(n.raw.begin() + 0x28, n.raw.begin() + 0x28 + 60);
    if (n.size > 60 && isize_ > 128) {
      const std::uint16_t extra = b.l16(0x80);
      const std::size_t hdr = 128u + extra;
      if (hdr + 4 <= n.raw.size() && b.l32(hdr) == 0xea020000) {
        std::size_t p = hdr + 4;
        const std::size_t base = p;
        while (p + 16 <= n.raw.size()) {
          const std::uint8_t nlen = b.u8(p), index = b.u8(p + 1);
          if (nlen == 0 && index == 0) break;
          const std::uint16_t voff = b.l16(p + 2);
          const std::uint32_t vsize = b.l32(p + 8);
          if (index == 7 && nlen == 4 && b.str(p + 16, 4) == "data") {
            auto v = b.span(base + voff, vsize);
            out.insert(out.end(), v.begin(), v.end());
            break;
          }
          p += (16u + nlen + 3u) & ~3u;
        }
      }
    }
    if (out.size() > n.size) out.resize(static_cast<std::size_t>(n.size));
    return out;
  }

  std::shared_ptr<Source> content(const Inode &n) const {
    if (n.flags & kEncrypt) throw Error("encrypted (fscrypt)");
    if (n.flags & kInline) return memory_source(inline_data(n));
    std::vector<Run> runs;
    if (n.flags & kExtents) {
      std::uint32_t visits = 0;
      std::uint64_t mapped = 0;
      extents(std::span(n.raw).subspan(0x28, 60), runs, 0, visits, mapped);
    } else {
      blockmap(n, runs);
    }
    // Runs past the size are cut; holes read as zeros.
    std::vector<Run> kept;
    for (Run r : runs) {
      if (r.logical >= n.size) continue;
      r.length = std::min(r.length, n.size - r.logical);
      kept.push_back(r);
    }
    return mapped_source(src_, std::move(kept), n.size);
  }

  void walk(TreeBuilder &tree, std::uint32_t parent, std::uint32_t ino, const Inode &dir, std::set<std::uint32_t> &seen,
            const Context &ctx, unsigned depth) {
    if (depth > ctx.limits.max_dir_depth) throw LimitError("ext directories nest too deep");
    if (!seen.insert(ino).second) throw Error("an ext directory contains itself");
    if (dir.size > (64u << 20)) throw LimitError("an ext directory over 64 MiB");
    // Sparse directories read as zeros: thousands of 64 MiB ones in a
    // small image. All of them together are capped.
    dir_bytes_ += dir.size;
    if (dir_bytes_ > (std::uint64_t{1} << 30)) throw LimitError("ext directories over 1 GiB in all");
    std::vector<std::byte> data;
    if (dir.flags & kInline) {
      data = inline_data(dir);
      // An inline directory starts with its parent's inode number.
      if (data.size() < 4) return;
      data.erase(data.begin(), data.begin() + 4);
    } else {
      auto s = content(dir);
      data = s->read_exact(0, s->size(), "an ext directory");
    }
    const bool typed = incompat_ & kIncompatFiletype;
    std::size_t p = 0;
    struct Child {
      std::string name;
      std::uint32_t ino;
    };
    std::vector<Child> kids;
    std::size_t damaged = 0;
    while (p + 8 <= data.size()) {
      ctx.check_cancelled();
      const std::uint32_t child = le32(data.data() + p);
      const std::uint16_t rec = le16(data.data() + p + 4);
      const std::uint16_t nlen = typed ? static_cast<std::uint8_t>(data[p + 6]) : le16(data.data() + p + 6);
      if (rec < 8 || (rec & 3) || p + rec > data.size()) {
        // A damaged block: skip to the next one.
        const std::size_t next = (p / bs_ + 1) * bs_;
        ++damaged;
        if (next <= p) break;
        p = next;
        continue;
      }
      if (child && nlen && 8u + nlen <= rec) {
        std::string name(reinterpret_cast<const char *>(data.data() + p + 8), nlen);
        if (name != "." && name != "..") kids.push_back({std::move(name), child});
      }
      p += rec;
      if (kids.size() > ctx.limits.max_entries) throw LimitError("an ext directory with too many entries");
    }
    if (damaged) warn(plural(damaged, "damaged directory block was", "damaged directory blocks were") + " skipped");
    // Not held while the subdirectories are read (256 levels of 64 MiB).
    std::vector<std::byte>().swap(data);
    for (const Child &k : kids) {
      Inode n;
      try {
        n = inode(k.ino);
      } catch (const Error &err) {
        warn(display_name(k.name) + ": " + err.what());
        continue;
      }
      Entry e;
      e.name = k.name;
      e.kind = kind_of_mode(n.mode);
      e.mode = n.mode & 07777;
      e.has_mode = true;
      e.uid = n.uid;
      e.gid = n.gid;
      e.has_owner = true;
      e.mtime = n.mtime;
      e.has_mtime = true;
      e.loc0 = k.ino;
      if (e.kind == Kind::file) {
        e.size = n.size;
        if (n.flags & kEncrypt) {
          e.note = "encrypted (fscrypt)";
          e.loc2 = UINT64_MAX;
        }
      } else if (e.kind == Kind::symlink) {
        e.size = n.size;
        try {
          if (n.size > 4096) throw Error("a symlink target over 4 KiB");
          std::vector<std::byte> t;
          const bool fast = !(n.flags & (kExtents | kInline)) && n.size < 60;
          if (fast) {
            t.assign(n.raw.begin() + 0x28, n.raw.begin() + 0x28 + static_cast<std::ptrdiff_t>(n.size));
          } else {
            auto s = content(n);
            t = s->read_exact(0, s->size(), "an ext symlink");
          }
          e.link_target.assign(reinterpret_cast<const char *>(t.data()), t.size());
        } catch (const Error &err) {
          e.note = std::string("unreadable link: ") + err.what();
        }
      }
      const bool dir = e.kind == Kind::directory;
      const std::uint32_t idx = tree.add_child(parent, std::move(e));
      if (dir) walk(tree, idx, k.ino, n, seen, ctx, depth + 1);
    }
  }

  std::shared_ptr<const Source> src_;
  std::uint32_t bs_ = 1024, inodes_count_ = 0, first_data_ = 0, bpg_ = 0, ipg_ = 0, groups_ = 0;
  std::uint32_t incompat_ = 0, first_meta_bg_ = 0;
  std::uint16_t isize_ = 128, desc_size_ = 32;
  bool sparse_ = false;
  std::uint64_t dir_bytes_ = 0;
};

}  // namespace

std::shared_ptr<FileSystem> open_ext(std::shared_ptr<const Source> src, std::string_view, const Context &ctx) {
  auto fs = std::make_shared<Ext>(std::move(src));
  fs->parse(ctx);
  return fs;
}

}  // namespace revkit::container::detail
