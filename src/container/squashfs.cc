// squashfs 4.0 (little-endian, as every Linux since 2.6.29 writes it):
// gzip, lzma, lzo, xz, lz4 and zstd; basic and extended inodes; data
// blocks (sparse ones too) and fragments. Older versions and the
// big-endian "sqsh" are recognised and refused with the reason.
#include "formats.hh"

#include <list>
#include <map>
#include <map>
#include <set>

namespace revkit::container::detail {
namespace {

constexpr std::uint32_t kMetaSize = 8192;

struct FileData {
  std::uint64_t start = 0;  // the first data block
  std::uint64_t size = 0;
  std::uint32_t fragment = 0xffffffff;
  std::uint32_t frag_offset = 0;
  std::vector<std::uint32_t> blocks;  // size words
};

class Squash final : public FileSystem {
 public:
  explicit Squash(std::shared_ptr<const Source> src) : src_(std::move(src)) {}

  void parse(const Context &ctx) {
    format_ = "squashfs";
    const auto sb = src_->read_exact(0, 96, "the squashfs superblock");
    Buf b(sb, "the squashfs superblock");
    if (b.str(0, 4) == "sqsh")
      throw Error("a big-endian squashfs (version " + std::to_string(b.b16(28)) + "." + std::to_string(b.b16(30)) +
                  "): only squashfs 4.0, little-endian, is read");
    const std::uint16_t major = b.l16(28), minor = b.l16(30);
    if (major != 4 || minor != 0)
      throw Error("squashfs version " + std::to_string(major) + "." + std::to_string(minor) +
                  " is not supported (only 4.0)");
    block_size_ = b.l32(12);
    const std::uint16_t block_log = b.l16(22);
    if (block_size_ < 4096 || block_size_ > (1u << 20) || (block_size_ & (block_size_ - 1)) ||
        block_log > 20 || (1u << block_log) != block_size_)  // a shift past 31 is undefined
      throw Error("squashfs block size " + std::to_string(block_size_) + " is invalid");
    const std::uint16_t comp = b.l16(20);
    static const char *names[] = {"", "gzip", "lzma", "lzo", "xz", "lz4", "zstd"};
    switch (comp) {
      case 1: codec_ = Codec::zlib; break;
      case 2: codec_ = Codec::lzma_alone; break;
      case 3: codec_ = Codec::lzo1x; break;
      case 4: codec_ = Codec::xz; break;
      case 5: codec_ = Codec::lz4_block; break;
      case 6: codec_ = Codec::zstd; break;
      default: throw Error("squashfs compression " + std::to_string(comp) + " is not known");
    }
    const std::uint32_t fragments = b.l32(16);
    const std::uint16_t ids = b.l16(26);
    const std::uint64_t root = b.l64(32);
    bytes_used_ = b.l64(40);
    const std::uint64_t id_table = b.l64(48);
    inode_table_ = b.l64(64);
    dir_table_ = b.l64(72);
    const std::uint64_t frag_table = b.l64(80);
    if (bytes_used_ > src_->size()) {
      warn("the image is truncated: it says " + std::to_string(bytes_used_) + " bytes, the file has " +
                          std::to_string(src_->size()));
      bytes_used_ = src_->size();
    }
    if (inode_table_ >= bytes_used_ || dir_table_ >= bytes_used_ || dir_table_ < inode_table_)
      throw Error("squashfs table offsets are out of range");
    // The id table: uids and gids by index.
    if (ids) {
      const std::uint32_t blocks = (ids + 2047u) / 2048u;
      const auto idx = src_->read_exact(id_table, 8ull * blocks, "the squashfs id index");
      std::vector<std::byte> all;
      for (std::uint32_t i = 0; i < blocks; ++i) {
        auto m = metablock(le64(idx.data() + 8 * i), nullptr);
        all.insert(all.end(), m.begin(), m.end());
      }
      if (all.size() < 4ull * ids) throw Error("the squashfs id table is short");
      for (std::uint32_t i = 0; i < ids; ++i) ids_.push_back(le32(all.data() + 4 * i));
    }
    // The fragment table.
    if (fragments && frag_table != UINT64_MAX) {
      if (fragments > (1u << 24)) throw LimitError("too many squashfs fragments");
      const std::uint32_t blocks = (fragments + 511u) / 512u;
      const auto idx = src_->read_exact(frag_table, 8ull * blocks, "the squashfs fragment index");
      std::vector<std::byte> all;
      for (std::uint32_t i = 0; i < blocks; ++i) {
        // The table's metablocks are written in order; one repeated made
        // 512 MiB of table from 260 KB.
        if (i && le64(idx.data() + 8 * i) <= le64(idx.data() + 8 * (i - 1)))
          throw Error("the squashfs fragment index isn't in order");
        auto m = metablock(le64(idx.data() + 8 * i), nullptr);
        all.insert(all.end(), m.begin(), m.end());
      }
      if (all.size() < 16ull * fragments) throw Error("the squashfs fragment table is short");
      for (std::uint32_t i = 0; i < fragments; ++i)
        frags_.push_back({le64(all.data() + 16 * i), le32(all.data() + 16 * i + 8)});
    }
    TreeBuilder tree(*this, ctx.limits);
    Entry rootdir;
    rootdir.kind = Kind::directory;
    std::set<std::uint64_t> seen;
    const Inode r = inode(root);
    if (r.kind != Kind::directory) throw Error("the squashfs root is not a directory");
    entries_[0].mode = r.mode;
    entries_[0].has_mode = true;
    entries_[0].mtime = r.mtime;
    entries_[0].has_mtime = true;
    walk(tree, 0, r, seen, ctx, 0);
    tree.finish();
    meta_cache_.clear();
    std::string what = summary_counts(*this);
    description_ = "squashfs 4.0, " + std::string(names[comp]) + ", " + what;
  }

  std::shared_ptr<Source> open(std::uint32_t entry, const Context &ctx) const override {
    Sink sink(ctx);
    read_file(entry, sink, ctx);
    return sink.finish();
  }

  std::vector<std::byte> head(std::uint32_t entry, std::uint64_t n, const Context &ctx) const override {
    Sink sink(ctx, n);
    read_file(entry, sink, ctx);
    return sink.finish()->head(n);
  }

 private:
  struct Inode {
    Kind kind = Kind::other;
    std::uint32_t mode = 0, uid = 0, gid = 0;
    std::int64_t mtime = 0;
    std::uint32_t number = 0;
    // directories
    std::uint64_t dir_block = 0;
    std::uint32_t dir_offset = 0, dir_size = 0;
    // files
    FileData file;
    std::string target;
  };

  // One metadata block at an absolute position: its bytes, and where the
  // next one starts.
  std::vector<std::byte> metablock(std::uint64_t pos, std::uint64_t *next) const {
    if (auto it = meta_cache_.find(pos); it != meta_cache_.end()) {
      if (next) *next = it->second.second;
      return it->second.first;
    }
    const auto hdr = src_->read_exact(pos, 2, "a squashfs metadata block");
    const std::uint16_t h = le16(hdr.data());
    const std::uint32_t size = h & 0x7fff;
    const bool raw = h & 0x8000;
    if (size == 0 || size > kMetaSize) throw Error("a squashfs metadata block of " + std::to_string(size) + " bytes");
    const auto data = src_->read_exact(pos + 2, size, "a squashfs metadata block");
    std::vector<std::byte> out;
    if (raw) {
      out = data;
    } else {
      out.resize(kMetaSize);
      out.resize(decompress_block(codec_, data, out));
    }
    if (next) *next = pos + 2 + size;
    if (meta_cache_.size() > 4096) meta_cache_.clear();
    meta_cache_[pos] = {out, pos + 2 + size};
    return out;
  }

  // Reads metadata from (block, offset) on, across blocks.
  class Meta {
   public:
    Meta(const Squash &fs, std::uint64_t block, std::uint32_t offset, std::uint64_t limit)
        : fs_(fs), next_(block), limit_(limit) {
      load();
      if (offset > cur_.size()) throw Error("a squashfs metadata offset is past its block");
      pos_ = offset;
    }
    std::vector<std::byte> take(std::size_t n) {
      std::vector<std::byte> out;
      out.reserve(n);
      while (out.size() < n) {
        if (pos_ == cur_.size()) load();
        const std::size_t k = std::min(n - out.size(), cur_.size() - pos_);
        out.insert(out.end(), cur_.begin() + static_cast<std::ptrdiff_t>(pos_),
                   cur_.begin() + static_cast<std::ptrdiff_t>(pos_ + k));
        pos_ += k;
      }
      return out;
    }
    std::uint16_t u16() { return le16(take(2).data()); }
    std::uint32_t u32() { return le32(take(4).data()); }
    std::uint64_t u64() { return le64(take(8).data()); }

   private:
    void load() {
      if (next_ >= limit_) throw Error("squashfs metadata runs past its table");
      if (++loaded_ > 65536) throw LimitError("squashfs metadata too long");
      cur_ = fs_.metablock(next_, &next_);
      pos_ = 0;
    }
    const Squash &fs_;
    std::uint64_t next_, limit_;
    std::vector<std::byte> cur_;
    std::size_t pos_ = 0;
    std::uint32_t loaded_ = 0;
  };

  std::uint32_t id(std::uint16_t i) const { return i < ids_.size() ? ids_[i] : 0; }

  Inode inode(std::uint64_t ref) const {
    const std::uint64_t block = inode_table_ + (ref >> 16);
    const std::uint32_t offset = ref & 0xffff;
    Meta m(*this, block, offset, dir_table_);
    Inode n;
    const std::uint16_t type = m.u16();
    n.mode = m.u16() & 07777;
    n.uid = id(m.u16());
    n.gid = id(m.u16());
    n.mtime = m.u32();
    n.number = m.u32();
    auto blocks_of = [&](FileData &f) {
      std::uint64_t count = f.size / block_size_;
      if (f.fragment == 0xffffffff && f.size % block_size_) ++count;
      if (count > (1u << 24)) throw LimitError("a squashfs file with too many blocks");
      f.blocks.resize(count);
      for (auto &w : f.blocks) w = m.u32();
    };
    switch (type) {
      case 1: {
        n.kind = Kind::directory;
        n.dir_block = m.u32();
        m.u32();  // nlink
        n.dir_size = m.u16();
        n.dir_offset = m.u16();
        m.u32();  // parent
        break;
      }
      case 8: {
        n.kind = Kind::directory;
        m.u32();  // nlink
        n.dir_size = m.u32();
        n.dir_block = m.u32();
        m.u32();  // parent
        m.u16();  // index count
        n.dir_offset = m.u16();
        m.u32();  // xattr
        break;
      }
      case 2: {
        n.kind = Kind::file;
        n.file.start = m.u32();
        n.file.fragment = m.u32();
        n.file.frag_offset = m.u32();
        n.file.size = m.u32();
        blocks_of(n.file);
        break;
      }
      case 9: {
        n.kind = Kind::file;
        n.file.start = m.u64();
        n.file.size = m.u64();
        m.u64();  // sparse
        m.u32();  // nlink
        n.file.fragment = m.u32();
        n.file.frag_offset = m.u32();
        m.u32();  // xattr
        blocks_of(n.file);
        break;
      }
      case 3:
      case 10: {
        n.kind = Kind::symlink;
        m.u32();  // nlink
        const std::uint32_t len = m.u32();
        if (len > 4096) throw Error("a squashfs symlink target over 4 KiB");
        auto t = m.take(len);
        n.target.assign(reinterpret_cast<const char *>(t.data()), t.size());
        break;
      }
      case 4:
      case 11: n.kind = Kind::block_device; break;
      case 5:
      case 12: n.kind = Kind::char_device; break;
      case 6:
      case 13: n.kind = Kind::fifo; break;
      case 7:
      case 14: n.kind = Kind::socket; break;
      default: throw Error("a squashfs inode of unknown type " + std::to_string(type));
    }
    return n;
  }

  void walk(TreeBuilder &tree, std::uint32_t parent, const Inode &dir, std::set<std::uint64_t> &seen,
            const Context &ctx, unsigned depth) {
    if (depth > ctx.limits.max_dir_depth) throw LimitError("squashfs directories nest too deep");
    if (dir.dir_size <= 3) return;  // empty: the size counts "." and ".."
    const std::uint64_t key = (dir.dir_block << 16) | dir.dir_offset;
    if (!seen.insert(key).second) throw Error("a squashfs directory contains itself");
    std::uint64_t left = dir.dir_size - 3;
    Meta m(*this, dir_table_ + dir.dir_block, dir.dir_offset, bytes_used_);
    struct Child {
      std::string name;
      std::uint64_t ref;
    };
    std::vector<Child> kids;
    while (left >= 12) {
      ctx.check_cancelled();
      const std::uint32_t count = m.u32() + 1;
      const std::uint32_t start = m.u32();
      m.u32();  // base inode number
      left -= 12;
      if (count > 256) throw Error("a squashfs directory header with " + std::to_string(count) + " entries");
      for (std::uint32_t i = 0; i < count; ++i) {
        if (left < 8) throw Error("a squashfs directory runs past its size");
        const std::uint16_t offset = m.u16();
        m.u16();  // inode number delta
        m.u16();  // type
        const std::uint32_t len = m.u16() + 1u;
        left -= 8;
        if (len > 256) throw Error("a squashfs directory entry name over 256 bytes");
        if (len > left) throw Error("a squashfs directory entry runs past its directory");
        auto nb = m.take(len);
        left -= len;
        kids.push_back({std::string(reinterpret_cast<const char *>(nb.data()), len),
                        (static_cast<std::uint64_t>(start) << 16) | offset});
        if (kids.size() > ctx.limits.max_entries) throw LimitError("a squashfs directory with too many entries");
      }
    }
    for (const Child &k : kids) {
      if (k.name.empty() || k.name == "." || k.name == "..") {
        warn("an entry named \"" + display_name(k.name) + "\" was skipped");
        continue;
      }
      const Inode n = inode(k.ref);
      // Each entry re-reads its inode: hard links to one 2^24-block file
      // copied 64 MiB each. Their block lists are shared, and all the
      // lists read are capped.
      block_words_ += n.file.blocks.size();
      if (block_words_ > (std::uint64_t{1} << 26)) throw LimitError("squashfs block lists over 256 MiB in all");
      Entry e;
      e.name = k.name;
      e.kind = n.kind;
      e.mode = n.mode;
      e.has_mode = true;
      e.uid = n.uid;
      e.gid = n.gid;
      e.has_owner = true;
      e.mtime = n.mtime;
      e.has_mtime = true;
      if (n.kind == Kind::file) {
        e.size = n.file.size;
        std::uint64_t stored = 0;
        for (std::uint32_t w : n.file.blocks) stored += w & 0xffffff;
        e.stored_size = stored;
        const auto [it, added] = file_by_ref_.emplace(k.ref, files_.size());
        e.loc0 = it->second;
        if (added) files_.push_back(n.file);
      } else if (n.kind == Kind::symlink) {
        e.link_target = n.target;
        e.size = n.target.size();
      }
      const std::uint32_t idx = tree.add_child(parent, std::move(e));
      if (n.kind == Kind::directory) walk(tree, idx, n, seen, ctx, depth + 1);
    }
  }

  // One data block: `word` is its size word (bit 24: stored), `want` the
  // bytes it decodes to.
  void block(std::uint64_t pos, std::uint32_t word, std::uint64_t want, std::vector<std::byte> &out) const {
    const std::uint32_t size = word & 0xffffff;
    if (size > block_size_ || pos + size > bytes_used_) throw Error("a squashfs data block is out of range");
    const auto data = src_->read_exact(pos, size, "a squashfs data block");
    if (word & 0x1000000) {
      out = data;
    } else {
      out.resize(block_size_);
      out.resize(decompress_block(codec_, data, out));
    }
    if (out.size() < want) throw Error("a squashfs data block decodes short");
    out.resize(static_cast<std::size_t>(want));
  }

  void read_file(std::uint32_t entry, Sink &sink, const Context &ctx) const {
    const Entry *e = &entries_.at(entry);
    if (e->kind == Kind::symlink || e->kind == Kind::hardlink) {
      auto t = resolve_link(entry);
      if (!t) throw Error("a link whose target isn't in the image");
      e = &entries_.at(*t);
    }
    if (e->kind != Kind::file) throw Error(display_name(e->name) + " is not a file");
    const FileData &f = files_.at(e->loc0);
    std::uint64_t pos = f.start, done = 0;
    std::vector<std::byte> buf;
    for (std::uint32_t w : f.blocks) {
      ctx.check_cancelled();
      const std::uint64_t want = std::min<std::uint64_t>(block_size_, f.size - done);
      if ((w & 0xffffff) == 0) {
        buf.assign(static_cast<std::size_t>(want), std::byte{0});  // sparse
      } else {
        block(pos, w, want, buf);
        pos += w & 0xffffff;
      }
      sink.append(buf);
      done += want;
      if (sink.full()) return;
    }
    if (f.fragment != 0xffffffff && done < f.size) {
      if (f.fragment >= frags_.size()) throw Error("a squashfs fragment index out of range");
      const auto &[start, word] = frags_[f.fragment];
      const std::uint64_t tail = f.size - done;
      std::shared_ptr<const std::vector<std::byte>> frag;
      {
        std::lock_guard lock(frag_mu_);
        for (auto it = frag_cache_.begin(); it != frag_cache_.end(); ++it)
          if (it->first == f.fragment) {
            frag = it->second;
            break;
          }
      }
      if (!frag) {
        const std::uint32_t size = word & 0xffffff;
        if (size > block_size_ || start + size > bytes_used_) throw Error("a squashfs fragment is out of range");
        const auto data = src_->read_exact(start, size, "a squashfs fragment");
        auto whole = std::make_shared<std::vector<std::byte>>();
        if (word & 0x1000000) {
          *whole = data;
        } else {
          whole->resize(block_size_);
          whole->resize(decompress_block(codec_, data, *whole));
        }
        frag = whole;
        std::lock_guard lock(frag_mu_);
        frag_cache_.emplace_front(f.fragment, frag);
        if (frag_cache_.size() > 8) frag_cache_.pop_back();
      }
      if (f.frag_offset > frag->size() || tail > frag->size() - f.frag_offset)
        throw Error("a squashfs file's tail lies outside its fragment");
      sink.append(std::span(*frag).subspan(f.frag_offset, static_cast<std::size_t>(tail)));
      done += tail;
    }
    if (done != f.size && !sink.full()) throw Error("a squashfs file's blocks don't add up to its size");
  }

  std::shared_ptr<const Source> src_;
  Codec codec_ = Codec::zlib;
  std::uint32_t block_size_ = 0;
  std::uint64_t bytes_used_ = 0, inode_table_ = 0, dir_table_ = 0;
  std::vector<std::uint32_t> ids_;
  std::vector<std::pair<std::uint64_t, std::uint32_t>> frags_;
  std::vector<FileData> files_;
  std::map<std::uint64_t, std::size_t> file_by_ref_;
  std::uint64_t block_words_ = 0;
  mutable std::map<std::uint64_t, std::pair<std::vector<std::byte>, std::uint64_t>> meta_cache_;
  mutable std::mutex frag_mu_;
  mutable std::list<std::pair<std::uint32_t, std::shared_ptr<const std::vector<std::byte>>>> frag_cache_;
};

}  // namespace

std::shared_ptr<FileSystem> open_squashfs(std::shared_ptr<const Source> src, std::string_view, const Context &ctx) {
  auto fs = std::make_shared<Squash>(std::move(src));
  fs->parse(ctx);
  return fs;
}

}  // namespace revkit::container::detail
