// cpio: newc ("070701"), newc with checksums ("070702"), odc ("070707")
// and the old binary format (0x71c7, either byte order), as initramfs and
// RPM payloads use them. Hard links (newc: several entries of one inode,
// the data with the last) are resolved to the entry holding the data.
#include "formats.hh"

#include <map>

namespace revkit::container::detail {
namespace {

std::uint64_t hexfield(Buf &b, std::size_t off, std::size_t n, const char *what) {
  std::uint64_t v = 0;
  for (std::size_t i = 0; i < n; ++i) {
    const char c = static_cast<char>(b.u8(off + i));
    int d;
    if (c >= '0' && c <= '9') d = c - '0';
    else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
    else throw Error(std::string("a malformed cpio ") + what);
    v = v * 16 + static_cast<std::uint64_t>(d);
  }
  return v;
}

std::uint64_t octfield(Buf &b, std::size_t off, std::size_t n, const char *what) {
  std::uint64_t v = 0;
  for (std::size_t i = 0; i < n; ++i) {
    const char c = static_cast<char>(b.u8(off + i));
    if (c < '0' || c > '7') throw Error(std::string("a malformed cpio ") + what);
    v = v * 8 + static_cast<std::uint64_t>(c - '0');
  }
  return v;
}

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

class Cpio final : public SliceFileSystem {
 public:
  using SliceFileSystem::SliceFileSystem;

  void parse(const Context &ctx) {
    format_ = "cpio";
    TreeBuilder tree(*this, ctx.limits);
    const std::uint64_t size = src_->size();
    std::uint64_t off = 0, members = 0;
    std::string variant;
    // newc hard links: (dev, inode) to the entries naming it.
    std::map<std::pair<std::uint64_t, std::uint64_t>, std::vector<std::uint32_t>> links;
    bool trailer = false;
    while (off < size) {
      ctx.check_cancelled();
      // Padding between archives (initramfs concatenates them).
      if (off + 6 > size) break;
      const auto magic = src_->read_exact(off, 6, "a cpio header");
      if (magic[0] == std::byte{0}) {
        std::uint64_t z = off;
        while (z < size && z - off < 4096) {
          std::byte c[1];
          src_->read(z, c);
          if (c[0] != std::byte{0}) break;
          ++z;
        }
        if (z == off || z >= size) break;
        off = z;
        continue;
      }
      std::uint32_t mode = 0, uid = 0, gid = 0, nlink = 0;
      std::uint64_t mtime = 0, filesize = 0, namesize = 0, ino = 0, dev = 0;
      std::uint64_t name_at = 0, header = 0, align = 1;
      const std::string m(reinterpret_cast<const char *>(magic.data()), 6);
      if (m == "070701" || m == "070702") {
        auto hb = src_->read_exact(off, 110, "a cpio header");
        Buf h(hb, "a cpio header");
        ino = hexfield(h, 6, 8, "inode");
        mode = static_cast<std::uint32_t>(hexfield(h, 14, 8, "mode"));
        uid = static_cast<std::uint32_t>(hexfield(h, 22, 8, "uid"));
        gid = static_cast<std::uint32_t>(hexfield(h, 30, 8, "gid"));
        nlink = static_cast<std::uint32_t>(hexfield(h, 38, 8, "nlink"));
        mtime = hexfield(h, 46, 8, "mtime");
        filesize = hexfield(h, 54, 8, "size");
        dev = hexfield(h, 62, 8, "dev") << 32 | hexfield(h, 70, 8, "dev");
        namesize = hexfield(h, 94, 8, "name size");
        header = 110;
        align = 4;
        variant = "newc";
      } else if (m == "070707") {
        auto hb = src_->read_exact(off, 76, "a cpio header");
        Buf h(hb, "a cpio header");
        dev = octfield(h, 6, 6, "dev");
        ino = octfield(h, 12, 6, "inode");
        mode = static_cast<std::uint32_t>(octfield(h, 18, 6, "mode"));
        uid = static_cast<std::uint32_t>(octfield(h, 24, 6, "uid"));
        gid = static_cast<std::uint32_t>(octfield(h, 30, 6, "gid"));
        nlink = static_cast<std::uint32_t>(octfield(h, 36, 6, "nlink"));
        mtime = octfield(h, 48, 11, "mtime");
        namesize = octfield(h, 59, 6, "name size");
        filesize = octfield(h, 65, 11, "size");
        header = 76;
        variant = "odc";
      } else if ((magic[0] == std::byte{0xc7} && magic[1] == std::byte{0x71}) ||
                 (magic[0] == std::byte{0x71} && magic[1] == std::byte{0xc7})) {
        const bool le = magic[0] == std::byte{0xc7};
        auto hb = src_->read_exact(off, 26, "a cpio header");
        auto u16 = [&](std::size_t o) {
          return le ? le16(hb.data() + o) : be16(hb.data() + o);
        };
        dev = u16(2);
        ino = u16(4);
        mode = u16(6);
        uid = u16(8);
        gid = u16(10);
        nlink = u16(12);
        mtime = static_cast<std::uint64_t>(u16(16)) << 16 | u16(18);
        namesize = u16(20);
        filesize = static_cast<std::uint64_t>(u16(22)) << 16 | u16(24);
        header = 26;
        align = 2;
        variant = "binary";
      } else {
        if (members == 0) throw Error("not a cpio archive");
        warn("stopped at offset " + std::to_string(off) + ": not a cpio header");
        break;
      }
      name_at = off + header;
      if (namesize == 0 || namesize > 65536) throw Error("a cpio name size out of range");
      auto nb = src_->read_exact(name_at, namesize, "a cpio name");
      std::string name(reinterpret_cast<const char *>(nb.data()), namesize);
      name.resize(strnlen(name.c_str(), name.size()));
      auto up = [&](std::uint64_t v) { return (v + align - 1) / align * align; };
      const std::uint64_t data = up(name_at + namesize);
      const std::uint64_t next = up(data + filesize);
      if (data > size || filesize > size - data) {
        warn("the last member is truncated");
        break;
      }
      if (name == "TRAILER!!!") {
        trailer = true;
        off = next;
        continue;  // another archive may follow (initramfs)
      }
      ++members;
      Entry e;
      e.kind = kind_of_mode(mode);
      e.mode = mode & 07777;
      e.has_mode = true;
      e.uid = uid;
      e.gid = gid;
      e.has_owner = true;
      e.mtime = static_cast<std::int64_t>(mtime);
      e.has_mtime = true;
      if (e.kind == Kind::file) {
        e.size = filesize;
        e.stored_size = filesize;
        e.loc0 = data;
        e.loc1 = filesize;
      } else if (e.kind == Kind::symlink) {
        if (filesize > 4096) throw Error("a cpio symlink target over 4 KiB");
        auto t = src_->read_exact(data, filesize, "a cpio symlink");
        e.link_target.assign(reinterpret_cast<const char *>(t.data()), t.size());
        e.size = filesize;
      }
      const bool regular = e.kind == Kind::file;
      const std::uint32_t idx = tree.add_path(name, std::move(e));
      if (regular && nlink > 1 && variant == "newc") links[{dev, ino}].push_back(idx);
      if (next <= off) throw Error("a cpio header doesn't advance");
      off = next;
    }
    if (members == 0 && !trailer) throw Error("an empty cpio archive");
    tree.finish();
    // newc stores a hard-linked file's data once, with its last name: the
    // others become hard links to it.
    for (const auto &[key, idxs] : links) {
      std::uint32_t holder = UINT32_MAX;
      for (std::uint32_t i : idxs)
        if (entries_[i].kind == Kind::file && entries_[i].size > 0) holder = i;
      if (holder == UINT32_MAX) continue;
      for (std::uint32_t i : idxs) {
        if (i == holder || entries_[i].size != 0) continue;
        entries_[i].kind = Kind::hardlink;
        std::string raw;
        for (const std::string &part : components_of(holder)) raw += "/" + part;
        entries_[i].link_target = raw;
        entries_[i].size = entries_[holder].size;
      }
    }
    description_ = "cpio archive (" + (variant.empty() ? std::string("empty") : variant) + "), " + summary_counts(*this);
  }
};

}  // namespace

std::shared_ptr<FileSystem> open_cpio(std::shared_ptr<const Source> src, std::string_view, const Context &ctx) {
  auto fs = std::make_shared<Cpio>(std::move(src));
  fs->parse(ctx);
  return fs;
}

}  // namespace revkit::container::detail
