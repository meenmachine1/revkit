// cramfs, little- or big-endian (mkcramfs -N), its superblock at 0 or after
// 512 bytes of padding: directories, files of zlib-compressed 4 KiB blocks
// (holes too), symlinks, devices. Blocks with the newer "extended block
// pointers" (direct and uncompressed blocks) are read as well.
#include "formats.hh"

#include <set>

namespace revkit::container::detail {
namespace {

constexpr std::uint32_t kPage = 4096;
constexpr std::uint32_t kFlagExtPointers = 0x800;

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

class Cramfs final : public FileSystem {
 public:
  explicit Cramfs(std::shared_ptr<const Source> src) : src_(std::move(src)) {}

  void parse(const Context &ctx) {
    format_ = "cramfs";
    auto at = src_->read_exact(0, 4, "the cramfs superblock");
    base_ = 0;
    if (le32(at.data()) != 0x28cd3d45 && be32(at.data()) != 0x28cd3d45) base_ = 512;
    const auto sb = src_->read_exact(base_, 76, "the cramfs superblock");
    if (le32(sb.data()) == 0x28cd3d45)
      be_ = false;
    else if (be32(sb.data()) == 0x28cd3d45)
      be_ = true;
    else
      throw Error("not a cramfs image");
    if (std::string(reinterpret_cast<const char *>(sb.data() + 16), 16) != "Compressed ROMFS")
      throw Error("a cramfs superblock without its signature");
    size_ = u32(sb.data() + 4);
    flags_ = u32(sb.data() + 8);
    if (size_ > src_->size()) {
      warn("the image is truncated");
      size_ = static_cast<std::uint32_t>(std::min<std::uint64_t>(src_->size(), UINT32_MAX));
    }
    std::string name(reinterpret_cast<const char *>(sb.data() + 48), 16);
    name.resize(strnlen(name.c_str(), name.size()));
    const Inode root = inode(std::span(sb).subspan(64, 12));
    TreeBuilder tree(*this, ctx.limits);
    entries_[0].mode = root.mode & 07777;
    entries_[0].has_mode = true;
    std::set<std::uint32_t> seen;
    walk(tree, 0, root, seen, ctx, 0);
    tree.finish();
    description_ = std::string("cramfs ") + (be_ ? "big" : "little") + "-endian" +
                   (name.empty() ? "" : " \"" + display_name(name) + "\"") + ", " + summary_counts(*this);
  }

  std::shared_ptr<Source> open(std::uint32_t entry, const Context &ctx) const override {
    const Entry *e = &entries_.at(entry);
    if (e->kind == Kind::symlink || e->kind == Kind::hardlink) {
      auto t = resolve_link(entry);
      if (!t) throw Error("a link whose target isn't in the image");
      e = &entries_.at(*t);
    }
    if (e->kind != Kind::file) throw Error(display_name(e->name) + " is not a file");
    Sink sink(ctx);
    data(e->loc0, e->size, sink, ctx);
    return sink.finish();
  }

  std::vector<std::byte> head(std::uint32_t entry, std::uint64_t n, const Context &ctx) const override {
    const Entry *e = &entries_.at(entry);
    if (e->kind != Kind::file) return FileSystem::head(entry, n, ctx);
    Sink sink(ctx, n);
    data(e->loc0, e->size, sink, ctx);
    return sink.finish()->head(n);
  }

 private:
  struct Inode {
    std::uint32_t mode = 0, uid = 0, gid = 0, size = 0, namelen = 0, offset = 0;
  };

  std::uint32_t u32(const std::byte *p) const { return be_ ? be32(p) : le32(p); }
  std::uint16_t u16(const std::byte *p) const { return be_ ? be16(p) : le16(p); }

  Inode inode(std::span<const std::byte> b) const {
    Inode n;
    n.mode = u16(b.data());
    n.uid = u16(b.data() + 2);
    const std::uint32_t a = u32(b.data() + 4), c = u32(b.data() + 8);
    if (be_) {
      n.size = a >> 8;
      n.gid = a & 0xff;
      n.namelen = c >> 26;
      n.offset = c & 0x3ffffff;
    } else {
      n.size = a & 0xffffff;
      n.gid = a >> 24;
      n.namelen = c & 0x3f;
      n.offset = c >> 6;
    }
    return n;
  }

  // A file's (or symlink's) bytes: the block pointer table at `offset`,
  // then the blocks.
  void data(std::uint64_t offset, std::uint64_t size, Sink &sink, const Context &ctx) const {
    if (size == 0) return;
    const std::uint64_t nblocks = (size + kPage - 1) / kPage;
    const std::uint64_t table = offset;
    const auto ptrs = src_->read_exact(table, 4 * nblocks, "a cramfs block table");
    std::uint64_t prev = table + 4 * nblocks;
    std::vector<std::byte> out(kPage);
    for (std::uint64_t i = 0; i < nblocks; ++i) {
      ctx.check_cancelled();
      std::uint32_t ptr = u32(ptrs.data() + 4 * i);
      const std::uint64_t want = std::min<std::uint64_t>(kPage, size - i * kPage);
      bool uncompressed = false;
      std::uint64_t start = prev, end;
      if (flags_ & kFlagExtPointers) {
        uncompressed = ptr & 0x80000000u;
        const bool direct = ptr & 0x40000000u;
        ptr &= 0x3fffffffu;
        if (direct) {
          // The block's start, in 4-byte units; its length follows from
          // the data (uncompressed: the page; compressed: a 2-byte prefix).
          start = static_cast<std::uint64_t>(ptr) << 2;
          if (uncompressed) {
            end = start + want;
          } else {
            const auto len = src_->read_exact(start, 2, "a cramfs block length");
            start += 2;
            end = start + u16(len.data());
          }
        } else {
          end = ptr;
        }
      } else {
        end = ptr;
      }
      if (end < start || end > size_) throw Error("a cramfs block pointer out of range");
      if (end == start) {
        // A hole (CRAMFS_FLAG_HOLES), or an empty block: zeros.
        std::vector<std::byte> zeros(static_cast<std::size_t>(want), std::byte{0});
        sink.append(zeros);
      } else {
        const auto comp = src_->read_exact(start, end - start, "a cramfs block");
        std::size_t got;
        if (uncompressed) {
          if (comp.size() < want) throw Error("a cramfs block decodes short");
          sink.append(std::span(comp).first(static_cast<std::size_t>(want)));
          got = static_cast<std::size_t>(want);
        } else {
          got = decompress_block(Codec::zlib, comp, out);
          if (got < want) throw Error("a cramfs block decodes short");
          sink.append(std::span(out).first(static_cast<std::size_t>(want)));
        }
        (void)got;
      }
      if (!(flags_ & kFlagExtPointers) || !(u32(ptrs.data() + 4 * i) & 0x40000000u)) prev = end;
      if (sink.full()) return;
    }
  }

  void walk(TreeBuilder &tree, std::uint32_t parent, const Inode &dir, std::set<std::uint32_t> &seen, const Context &ctx,
            unsigned depth) {
    if (depth > ctx.limits.max_dir_depth) throw LimitError("cramfs directories nest too deep");
    if (dir.size == 0) return;
    if (!seen.insert(dir.offset).second) throw Error("a cramfs directory contains itself");
    const std::uint64_t start = static_cast<std::uint64_t>(dir.offset) << 2;
    auto bytes = src_->read_exact(start, dir.size, "a cramfs directory");
    // Subdirectories are read after this one is released (256 levels of
    // overlapping 16 MiB directories were held at once).
    std::vector<std::pair<std::uint32_t, Inode>> subdirs;
    std::size_t p = 0;
    while (p + 12 <= bytes.size()) {
      ctx.check_cancelled();
      const Inode n = inode(std::span(bytes).subspan(p, 12));
      const std::size_t nlen = n.namelen * 4u;
      if (nlen == 0 || p + 12 + nlen > bytes.size()) throw Error("a cramfs directory entry runs past its directory");
      std::string name(reinterpret_cast<const char *>(bytes.data() + p + 12), nlen);
      name.resize(strnlen(name.c_str(), name.size()));
      p += 12 + nlen;
      if (name.empty() || name == "." || name == "..") continue;
      Entry e;
      e.name = name;
      e.kind = kind_of_mode(n.mode);
      e.mode = n.mode & 07777;
      e.has_mode = true;
      e.uid = n.uid;
      e.gid = n.gid;
      e.has_owner = true;
      if (e.kind == Kind::file) {
        e.size = n.size;
        e.loc0 = static_cast<std::uint64_t>(n.offset) << 2;
        if (n.offset == 0 && n.size) {
          e.note = "no data";
          e.loc2 = UINT64_MAX;
        }
      } else if (e.kind == Kind::symlink) {
        try {
          if (n.size > 4096) throw Error("a symlink target over 4 KiB");
          Context small;
          small.limits.max_file_bytes = 8192;
          Sink sink(small);
          data(static_cast<std::uint64_t>(n.offset) << 2, n.size, sink, small);
          auto s = sink.finish();
          const auto t = s->read_exact(0, s->size(), "a cramfs symlink");
          e.link_target.assign(reinterpret_cast<const char *>(t.data()), t.size());
          e.size = t.size();
        } catch (const Error &err) {
          e.note = std::string("unreadable link: ") + err.what();
        }
      }
      const bool d = e.kind == Kind::directory;
      const std::uint32_t idx = tree.add_child(parent, std::move(e));
      if (d) subdirs.emplace_back(idx, n);
    }
    std::vector<std::byte>().swap(bytes);
    for (const auto &[idx, n] : subdirs) walk(tree, idx, n, seen, ctx, depth + 1);
  }

  std::shared_ptr<const Source> src_;
  std::uint64_t base_ = 0;
  std::uint32_t size_ = 0, flags_ = 0;
  bool be_ = false;
};

}  // namespace

std::shared_ptr<FileSystem> open_cramfs(std::shared_ptr<const Source> src, std::string_view, const Context &ctx) {
  auto fs = std::make_shared<Cramfs>(std::move(src));
  fs->parse(ctx);
  return fs;
}

}  // namespace revkit::container::detail
