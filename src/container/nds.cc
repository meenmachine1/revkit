// Nintendo DS formats as file systems (docs/filesystems.md, docs/nds.md):
//
//   nds   a .nds ROM image, laid out as ndstool extracts one: header.bin,
//         arm9.bin and arm7.bin (the programs, the ARM9 decompressed when
//         BLZ-compressed, each with its language and load address so it
//         imports as a raw program), y9.bin and y7.bin (the overlay tables),
//         overlay/overlay_NNNN.bin (decompressed when compressed),
//         banner.bin, and files/: NitroFS, the ROM's own file system (ds-rom's
//         extract layout, which dsd projects use)
//   narc  a NARC archive (BTAF, BTNF, GMIF), by its names or by index
//
// Inside both, a file whose bytes are LZ10, LZ11, Huffman or RLE data
// throughout (nds::looks_compressed) shows decompressed, its note saying
// so. The formats are revkit::nds's (src/nds).
#include "formats.hh"

#include "revkit/nds/compress.hh"
#include "revkit/nds/rom.hh"

#include <cstdio>
#include <map>

namespace revkit::container::detail {
namespace {

std::span<const std::uint8_t> u8span(const std::vector<std::byte> &v) {
  return {reinterpret_cast<const std::uint8_t *>(v.data()), v.size()};
}

// A member at [off, off+len) of `src`: plain, or decompressed when its
// bytes are a DS compression throughout.
Entry Member(const Source &src, std::uint64_t off, std::uint64_t len, const Context &ctx) {
  Entry e;
  e.kind = Kind::file;
  e.size = len;
  e.stored_size = len;
  e.loc0 = off;
  e.loc1 = len;
  if (len >= 8 && len <= (64u << 20)) {
    std::vector<std::byte> head = src.read_exact(off, std::min<std::uint64_t>(len, 8), "a DS file's header");
    if (nds::compression_header(u8span(head))) {
      std::vector<std::byte> all = src.read_exact(off, len, "a DS file");
      const std::size_t max = static_cast<std::size_t>(std::min<std::uint64_t>(ctx.limits.max_file_bytes, 64u << 20));
      if (nds::looks_compressed(u8span(all), max)) {
        auto h = nds::compression_header(u8span(all));
        e.size = h->size;
        e.loc2 = 1 + static_cast<std::uint64_t>(Codec::nds_lz);
        e.note = std::string(nds::to_string(h->type)) + " compressed (" + std::to_string(len) + " bytes stored)";
      }
    }
  }
  return e;
}

class NdsRomFs final : public SliceFileSystem {
 public:
  using SliceFileSystem::SliceFileSystem;

  void parse(const Context &ctx) {
    format_ = "nds";
    const std::uint64_t size = src_->size();
    auto hb = src_->read_exact(0, std::min<std::uint64_t>(size, 0x200), "the DS header");
    std::string e;
    std::optional<nds::NdsHeader> h = nds::parse_nds_header(u8span(hb), &e, size);
    if (!h) throw Error(e);
    TreeBuilder tree(*this, ctx.limits);
    auto plain = [&](const std::string &path, std::uint64_t off, std::uint64_t len, const char *note = nullptr) {
      if (len == 0 || off > size || len > size - off) return;
      Entry m;
      m.kind = Kind::file;
      m.size = m.stored_size = m.loc1 = len;
      m.loc0 = off;
      if (note) m.note = note;
      tree.add_path(path, std::move(m));
    };
    plain("header.bin", 0, std::min<std::uint64_t>(size, h->header_size && h->header_size <= 0x4000 ? h->header_size : 0x200));
    // The ARM9: decompressed when its module parameters say so.
    {
      Entry a9;
      a9.kind = Kind::file;
      a9.loc0 = h->arm9_rom_offset;
      a9.loc1 = h->arm9_size;
      a9.size = a9.stored_size = h->arm9_size;
      a9.language = "ARM:LE:32:v5t";
      a9.load_address = h->arm9_ram_address;
      if (h->arm9_size <= (64u << 20)) {
        auto arm9 = src_->read_exact(h->arm9_rom_offset, h->arm9_size, "the ARM9 program");
        std::optional<std::uint32_t> footer;
        const std::uint64_t fo = std::uint64_t{h->arm9_rom_offset} + h->arm9_size;
        if (fo + 12 <= size) {
          auto f = src_->read_exact(fo, 12, "the ARM9 footer");
          if (le32(f.data()) == 0xdec00621u) footer = le32(f.data() + 4);
        }
        if (auto p = nds::find_module_params(u8span(arm9), h->arm9_ram_address, footer);
            p && p->compressed_static_end > h->arm9_ram_address &&
            p->compressed_static_end - h->arm9_ram_address <= h->arm9_size) {
          const std::uint64_t packed = p->compressed_static_end - h->arm9_ram_address;
          if (auto f = nds::blz_footer(u8span(arm9).subspan(0, packed))) {
            a9.loc1 = packed;
            a9.size = packed + f->extra + (h->arm9_size - packed);
            a9.loc2 = 1 + static_cast<std::uint64_t>(Codec::nds_blz);
            a9.note = "BLZ compressed in the ROM (" + std::to_string(h->arm9_size) + " bytes stored); with its autoloads";
            if (packed != h->arm9_size) a9.size = packed + f->extra;  // what follows is left out
          }
        }
      }
      tree.add_path("arm9.bin", std::move(a9));
    }
    {
      Entry a7;
      a7.kind = Kind::file;
      a7.loc0 = h->arm7_rom_offset;
      a7.loc1 = a7.size = a7.stored_size = h->arm7_size;
      a7.language = "ARM:LE:32:v4t";
      a7.load_address = h->arm7_ram_address;
      if (h->arm7_size && h->arm7_rom_offset <= size && h->arm7_size <= size - h->arm7_rom_offset)
        tree.add_path("arm7.bin", std::move(a7));
    }
    plain("y9.bin", h->arm9_overlay_offset, h->arm9_overlay_size);
    plain("y7.bin", h->arm7_overlay_offset, h->arm7_overlay_size);
    if (h->banner_offset) plain("banner.bin", h->banner_offset, std::min<std::uint64_t>(0x840, size > h->banner_offset ? size - h->banner_offset : 0));
    // The file system.
    std::vector<nds::NdsFile> files;
    std::vector<nds::NdsDirectory> dirs;
    std::vector<std::string> warnings;
    if (h->fat_size && h->fat_offset <= size && h->fat_size <= size - h->fat_offset && h->fat_size <= (8u << 20)) {
      auto fat = src_->read_exact(h->fat_offset, h->fat_size, "the FAT");
      std::vector<std::byte> fnt;
      if (h->fnt_size && h->fnt_offset <= size && h->fnt_size <= size - h->fnt_offset && h->fnt_size <= (8u << 20))
        fnt = src_->read_exact(h->fnt_offset, h->fnt_size, "the FNT");
      nds::parse_nitrofs(u8span(fnt), u8span(fat), files, dirs, warnings, ctx.limits.max_entries);
    }
    for (const std::string &w : warnings) warn(w);
    for (const nds::NdsDirectory &d : dirs)
      if (d.path != "/") tree.directory("files" + d.path);
    // Overlays: named by the tables; the rest of the unnamed ids as files.
    std::map<std::uint32_t, std::pair<std::string, nds::NdsOverlay>> overlays;
    auto table = [&](std::uint32_t off, std::uint32_t len, const char *prefix) {
      if (!len || off > size || len > size - off || len > (1u << 20)) return;
      auto t = src_->read_exact(off, len, "an overlay table");
      for (std::size_t o = 0; o + 32 <= t.size(); o += 32) {
        nds::NdsOverlay v;
        const std::byte *p = t.data() + o;
        v.id = le32(p);
        v.ram_address = le32(p + 4);
        v.file_id = le32(p + 24);
        const std::uint32_t last = le32(p + 28);
        v.compressed = (last >> 24) & 1;
        v.compressed_size = last & 0xffffff;
        char name[48];
        std::snprintf(name, sizeof name, "%s/overlay_%04u.bin", prefix, v.id);
        overlays.emplace(v.file_id, std::make_pair(std::string(name), v));
      }
    };
    table(h->arm9_overlay_offset, h->arm9_overlay_size, "overlay");
    table(h->arm7_overlay_offset, h->arm7_overlay_size, "overlay7");
    std::size_t named = 0;
    for (const nds::NdsFile &f : files) {
      ctx.check_cancelled();
      if (f.end <= f.start) continue;
      const std::uint64_t len = f.end - f.start;
      if (auto it = overlays.find(f.id); it != overlays.end() && f.path.empty()) {
        Entry o;
        o.kind = Kind::file;
        o.loc0 = f.start;
        o.loc1 = o.size = o.stored_size = len;
        o.language = it->second.first.starts_with("overlay7/") ? "ARM:LE:32:v4t" : "ARM:LE:32:v5t";
        o.load_address = it->second.second.ram_address;
        if (it->second.second.compressed) {
          const std::uint64_t packed = it->second.second.compressed_size && it->second.second.compressed_size <= len
                                           ? it->second.second.compressed_size
                                           : len;
          auto tail = src_->read_exact(f.start, packed, "an overlay");
          if (auto foot = nds::blz_footer(u8span(tail))) {
            o.loc1 = packed;
            o.size = packed + foot->extra;
            o.loc2 = 1 + static_cast<std::uint64_t>(Codec::nds_blz);
            o.note = "BLZ compressed (" + std::to_string(packed) + " bytes stored)";
          }
        }
        tree.add_path(it->second.first, std::move(o));
        continue;
      }
      if (f.path.empty()) continue;
      tree.add_path("files" + f.path, Member(*src_, f.start, len, ctx));
      ++named;
    }
    tree.finish();
    description_ = "Nintendo DS ROM \"" + h->title + "\" (" + h->game_code + "), " + plural(named, "file", "files") +
                   ", " + plural(overlays.size(), "overlay", "overlays");
  }
};

class NarcFs final : public SliceFileSystem {
 public:
  using SliceFileSystem::SliceFileSystem;

  void parse(const Context &ctx) {
    format_ = "narc";
    const std::uint64_t size = src_->size();
    if (size > (256u << 20)) throw LimitError("a NARC over 256 MiB");
    auto all = src_->read_exact(0, size, "the NARC");
    std::string e;
    std::optional<nds::Narc> n = nds::parse_narc(u8span(all), &e, ctx.limits.max_entries);
    if (!n) throw Error(e);
    for (const std::string &w : n->warnings) warn(w);
    TreeBuilder tree(*this, ctx.limits);
    for (const std::string &d : n->directories) tree.directory(d.substr(1));
    for (const nds::NarcFile &f : n->files) {
      ctx.check_cancelled();
      tree.add_path(f.path.substr(1), Member(*src_, f.offset, f.size, ctx));
    }
    tree.finish();
    description_ = "NARC archive, " + plural(n->files.size(), "file", "files");
  }
};

}  // namespace

std::shared_ptr<FileSystem> open_nds(std::shared_ptr<const Source> src, std::string_view, const Context &ctx) {
  auto fs = std::make_shared<NdsRomFs>(std::move(src));
  fs->parse(ctx);
  return fs;
}

std::shared_ptr<FileSystem> open_narc(std::shared_ptr<const Source> src, std::string_view, const Context &ctx) {
  auto fs = std::make_shared<NarcFs>(std::move(src));
  fs->parse(ctx);
  return fs;
}

}  // namespace revkit::container::detail
