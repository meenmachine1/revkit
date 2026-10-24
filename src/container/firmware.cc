// Firmware packages and disk images: U-Boot legacy images (uImage), Android
// boot images (v0-v4), UF2 (Microsoft's USB flashing format, converted to
// flat images per family and address range) and partition tables (MBR with
// logical partitions, GPT). Members whose header names their processor
// carry the language and load address, so a batch import can take them as
// raw images.
#include "formats.hh"

#include <algorithm>
#include <array>
#include <cstdio>
#include <map>
#include <set>

namespace revkit::container::detail {
namespace {

std::string hex32(std::uint64_t v) {
  char buf[24];
  std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(v));
  return buf;
}

std::string safe(std::string s) {
  for (char &c : s)
    if (c == '/' || static_cast<unsigned char>(c) < 0x20) c = '_';
  while (!s.empty() && s.back() == ' ') s.pop_back();
  if (s == "." || s == "..") s = "_" + s;
  return s;
}

// ---- uImage ------------------------------------------------------------------

struct UArch {
  unsigned id;
  const char *name;
  const char *language;  // "" when the byte order isn't settled
};
constexpr UArch kUArch[] = {
    {2, "ARM", "ARM:LE:32:v8"},          {3, "x86", "x86:LE:32:default"}, {5, "MIPS", ""},
    {6, "MIPS64", ""},                   {7, "PowerPC", "PowerPC:BE:32:default"}, {9, "SuperH", ""},
    {10, "SPARC", ""},                   {11, "SPARC64", ""},            {12, "68000", ""},
    {14, "MicroBlaze", ""},              {15, "Nios II", ""},            {16, "Blackfin", ""},
    {20, "x86-64", "x86:LE:64:default"}, {21, "Xtensa", ""},             {22, "AArch64", "AARCH64:LE:64:v8A"},
    {26, "RISC-V", ""},
};

class UImage final : public SliceFileSystem {
 public:
  using SliceFileSystem::SliceFileSystem;

  void parse(const Context &ctx) {
    format_ = "uimage";
    const auto hb = src_->read_exact(0, 64, "the uImage header");
    Buf h(hb, "the uImage header");
    if (h.b32(0) != 0x27051956) throw Error("not a uImage");
    std::array<std::byte, 64> copy;
    std::memcpy(copy.data(), hb.data(), 64);
    std::memset(copy.data() + 4, 0, 4);
    if (crc32_ieee(copy) != h.b32(4)) throw Error("the uImage header checksum doesn't match");
    const std::uint32_t size = h.b32(12), load = h.b32(16), ep = h.b32(20), dcrc = h.b32(24);
    const std::uint8_t arch = h.u8(29), type = h.u8(30), comp = h.u8(31);
    std::string name = safe(h.cstr(32, 32));
    const UArch *a = nullptr;
    for (const UArch &u : kUArch)
      if (u.id == arch) a = &u;
    if (64ull + size > src_->size()) {
      warn("the image is truncated");
    } else {
      const auto data = src_->read_exact(64, size, "the uImage data");
      if (crc32_ieee(data) != dcrc) warn("the data checksum doesn't match");
    }
    const std::uint64_t avail = std::min<std::uint64_t>(size, src_->size() > 64 ? src_->size() - 64 : 0);
    static const char *types[] = {"invalid", "standalone", "kernel", "ramdisk", "multi", "firmware", "script",
                                  "filesystem", "flat_dt"};
    const std::string tname = type < 9 ? types[type] : "type " + std::to_string(type);
    TreeBuilder tree(*this, ctx.limits);
    // Compressed payloads: the decompressed data is the member (the
    // header's processor and load address are about it).
    std::uint64_t codec = 0;
    switch (comp) {
      case 0: break;
      case 1: codec = 1 + static_cast<std::uint64_t>(Codec::gzip); break;
      case 2: codec = 1 + static_cast<std::uint64_t>(Codec::bzip2); break;
      case 3: codec = 1 + static_cast<std::uint64_t>(Codec::lzma_alone); break;
      case 5: codec = 1 + static_cast<std::uint64_t>(Codec::lz4_frame); break;
      case 6: codec = 1 + static_cast<std::uint64_t>(Codec::zstd); break;
      default: codec = UINT64_MAX;
    }
    auto add = [&](std::string member, std::uint64_t off, std::uint64_t len, bool primary) {
      Entry e;
      e.kind = Kind::file;
      e.name = member;
      e.loc0 = off;
      e.loc1 = len;
      e.loc2 = primary ? codec : 0;
      e.size = primary && codec ? UINT64_MAX : len;
      e.stored_size = len;
      if (primary && codec == UINT64_MAX) e.note = "LZO compression (lzop) is not supported";
      if (primary && a && (type == 2 || type == 1 || type == 5) && codec != UINT64_MAX) {
        e.language = a->language;
        e.load_address = load;
      }
      tree.add_child(0, std::move(e));
    };
    if (type == 4) {
      // Multi-file: a list of sizes ending in 0, then each image padded to 4.
      std::vector<std::uint32_t> sizes;
      std::uint64_t p = 64;
      for (;;) {
        if (sizes.size() > 256) throw Error("a uImage with too many parts");
        const auto w = src_->read_exact(p, 4, "the uImage part list");
        p += 4;
        const std::uint32_t s = be32(w.data());
        if (s == 0) break;
        sizes.push_back(s);
      }
      for (std::size_t i = 0; i < sizes.size(); ++i) {
        if (p + sizes[i] > src_->size()) throw Error("a uImage part runs past the file");
        add("part" + std::to_string(i), p, sizes[i], false);
        p += (sizes[i] + 3u) & ~3u;
      }
    } else {
      add(name.empty() ? tname : name, 64, avail, true);
    }
    tree.finish();
    description_ = "U-Boot image (" + tname + ", " + (a ? a->name : "arch " + std::to_string(arch)) + ", load " +
                   hex32(load) + ", entry " + hex32(ep) + ")";
  }
};

// ---- Android boot images -------------------------------------------------------

class AndroidBoot final : public SliceFileSystem {
 public:
  using SliceFileSystem::SliceFileSystem;

  void parse(const Context &ctx) {
    format_ = "android-boot";
    const auto hb = src_->read_exact(0, std::min<std::uint64_t>(src_->size(), 4096), "the boot image header");
    Buf h(hb, "the boot image header");
    if (h.str(0, 8) == "VNDRBOOT") return vendor_boot(h, hb, ctx);
    if (h.str(0, 8) != "ANDROID!") throw Error("not an Android boot image");
    const std::uint32_t version = h.l32(40);
    TreeBuilder tree(*this, ctx.limits);
    std::uint64_t page, pos;
    auto add = [&](const char *name, std::uint64_t size, std::optional<std::uint64_t> load) {
      if (size == 0) return;
      if (pos > src_->size() || size > src_->size() - pos) {
        warn(std::string(name) + " runs past the file");
        return;
      }
      Entry e;
      e.kind = Kind::file;
      e.name = name;
      e.loc0 = pos;
      e.loc1 = size;
      e.size = size;
      e.stored_size = size;
      e.load_address = load;
      tree.add_child(0, std::move(e));
      pos += (size + page - 1) / page * page;
    };
    std::string cmdline;
    if (version >= 3 && version < 16) {
      page = 4096;
      pos = page;
      const std::uint32_t kernel = h.l32(8), ramdisk = h.l32(12);
      cmdline = h.cstr(44, 1536);
      add("kernel", kernel, std::nullopt);
      add("ramdisk", ramdisk, std::nullopt);
      if (version >= 4 && hb.size() >= 1584) add("boot_signature", h.l32(1580), std::nullopt);
    } else {
      page = h.l32(36);
      if (page < 2048 || page > 65536 || (page & (page - 1))) throw Error("a boot image page size of " + std::to_string(page));
      pos = page;
      const std::uint32_t kernel = h.l32(8), kaddr = h.l32(12), ramdisk = h.l32(16), raddr = h.l32(20);
      const std::uint32_t second = h.l32(24), saddr = h.l32(28);
      cmdline = h.cstr(64, 512);
      add("kernel", kernel, kaddr);
      add("ramdisk", ramdisk, raddr);
      add("second", second, saddr);
      if (version >= 1 && hb.size() >= 1648) add("recovery_dtbo", h.l32(1632), std::nullopt);
      if (version >= 2 && hb.size() >= 1660) add("dtb", h.l32(1648), h.l64(1652));
    }
    tree.finish();
    description_ = "Android boot image v" + std::to_string(version < 16 ? version : 0) +
                   (cmdline.empty() ? "" : ", cmdline \"" + display_name(cmdline.substr(0, 80)) + "\"");
  }

 private:
  // A vendor boot image (v3, v4): the vendor ramdisk (v4: the ramdisks its
  // table names), the DTB, the bootconfig.
  void vendor_boot(const Buf &h, const std::vector<std::byte> &hb, const Context &ctx) {
    const std::uint32_t version = h.l32(8), page = h.l32(12);
    if (version < 3 || version > 4) throw Error("vendor boot image version " + std::to_string(version) + " is not known");
    if (page < 2048 || page > 65536 || (page & (page - 1))) throw Error("a boot image page size of " + std::to_string(page));
    const std::uint32_t kaddr = h.l32(16), raddr = h.l32(20), ramdisk = h.l32(24);
    const std::string cmdline = h.cstr(28, 2048);
    const std::string name = h.cstr(2080, 16);
    const std::uint32_t hsize = h.l32(2096), dtb = h.l32(2100);
    const std::uint64_t daddr = h.l64(2104);
    std::uint32_t table = 0, table_n = 0, table_esize = 0, bootconfig = 0;
    if (version >= 4) {
      table = h.l32(2112);
      table_n = h.l32(2116);
      table_esize = h.l32(2120);
      bootconfig = h.l32(2124);
    }
    (void)hb;
    auto pages = [&](std::uint64_t n) { return (n + page - 1) / page * page; };
    TreeBuilder tree(*this, ctx.limits);
    auto add = [&](std::string member, std::uint64_t at, std::uint64_t size, std::optional<std::uint64_t> load,
                   std::string note) {
      if (size == 0) return;
      if (at > src_->size() || size > src_->size() - at) {
        warn(member + " runs past the file");
        return;
      }
      Entry e;
      e.kind = Kind::file;
      e.name = std::move(member);
      e.loc0 = at;
      e.loc1 = e.size = e.stored_size = size;
      e.load_address = load;
      e.note = std::move(note);
      tree.add_child(0, std::move(e));
    };
    const std::uint64_t ramdisk_at = pages(hsize);
    const std::uint64_t dtb_at = ramdisk_at + pages(ramdisk);
    const std::uint64_t table_at = dtb_at + pages(dtb);
    const std::uint64_t bootconfig_at = table_at + pages(table);
    if (version >= 4 && table_n && table_esize >= 108 && table_n <= 4096) {
      // Each entry: size, offset in the ramdisk section, type, name[32].
      static const char *types[] = {"none", "platform", "recovery", "dlkm"};
      const auto t = src_->read_exact(table_at, std::uint64_t{table_n} * table_esize, "the vendor ramdisk table");
      for (std::uint32_t i = 0; i < table_n; ++i) {
        Buf e{std::span<const std::byte>(t).subspan(std::size_t{i} * table_esize, table_esize), "a vendor ramdisk entry"};
        const std::uint32_t size = e.l32(0), off = e.l32(4), type = e.l32(8);
        std::string rname = safe(e.cstr(12, 32));
        if (off > ramdisk || size > ramdisk - off) {
          warn("vendor ramdisk " + std::to_string(i) + " lies outside the ramdisk section");
          continue;
        }
        add("vendor_ramdisk" + std::string(rname.empty() ? "" : "-" + rname) + (table_n > 1 && rname.empty() ? std::to_string(i) : ""),
            ramdisk_at + off, size, raddr, std::string("type ") + (type < 4 ? types[type] : std::to_string(type).c_str()));
      }
    } else {
      add("vendor_ramdisk", ramdisk_at, ramdisk, raddr, "");
    }
    add("dtb", dtb_at, dtb, daddr, "");
    add("bootconfig", bootconfig_at, bootconfig, std::nullopt, "");
    tree.finish();
    description_ = "Android vendor boot image v" + std::to_string(version) + (name.empty() ? "" : " \"" + display_name(name) + "\"") +
                   ", kernel at " + hex32(kaddr) +
                   (cmdline.empty() ? "" : ", cmdline \"" + display_name(cmdline.substr(0, 80)) + "\"");
  }
};

// ---- UF2 -----------------------------------------------------------------------

struct Family {
  std::uint32_t id;
  const char *name;
  const char *language;
};
constexpr Family kFamilies[] = {
    {0xe48bff56, "rp2040", "ARM:LE:32:Cortex"},      {0xe48bff59, "rp2350-arm-s", "ARM:LE:32:v8-m"},
    {0xe48bff5b, "rp2350-arm-ns", "ARM:LE:32:v8-m"}, {0xe48bff5a, "rp2350-riscv", "RISCV:LE:32:default"},
    {0x68ed2b88, "samd21", "ARM:LE:32:Cortex"},      {0x55114460, "samd51", "ARM:LE:32:Cortex"},
    {0xada52840, "nrf52840", "ARM:LE:32:Cortex"},    {0x1b57745f, "nrf52", "ARM:LE:32:Cortex"},
    {0x621e937a, "nrf52833", "ARM:LE:32:Cortex"},    {0x57755a57, "stm32f4", "ARM:LE:32:Cortex"},
    {0x5ee21072, "stm32f1", "ARM:LE:32:Cortex"},     {0x5d1a0a2e, "stm32f2", "ARM:LE:32:Cortex"},
    {0x6b846188, "stm32f3", "ARM:LE:32:Cortex"},     {0x53b80f00, "stm32f7", "ARM:LE:32:Cortex"},
    {0x300f5633, "stm32g0", "ARM:LE:32:Cortex"},     {0x4c71240a, "stm32g4", "ARM:LE:32:Cortex"},
    {0x6db66082, "stm32h7", "ARM:LE:32:Cortex"},     {0x202e3a91, "stm32l0", "ARM:LE:32:Cortex"},
    {0x1e1f432d, "stm32l1", "ARM:LE:32:Cortex"},     {0x00ff6919, "stm32l4", "ARM:LE:32:Cortex"},
    {0x04240bdf, "stm32l5", "ARM:LE:32:v8-m"},       {0x70d16653, "stm32wb", "ARM:LE:32:Cortex"},
    {0x21460ff0, "stm32wl", "ARM:LE:32:Cortex"},     {0x4fb2d5bd, "imxrt10xx", "ARM:LE:32:Cortex"},
    {0x2abc77ec, "lpc55", "ARM:LE:32:v8-m"},         {0x1c5f21b0, "esp32", "Xtensa:LE:32:default"},
    {0xbfdd4eee, "esp32s2", "Xtensa:LE:32:default"}, {0xc47e5767, "esp32s3", "Xtensa:LE:32:default"},
    {0xd42ba06c, "esp32c3", "RISCV:LE:32:default"},  {0x2b88d29c, "esp32c2", "RISCV:LE:32:default"},
    {0x540ddf62, "esp32c6", "RISCV:LE:32:default"},  {0x332726f6, "esp32h2", "RISCV:LE:32:default"},
    {0x647824b6, "gd32vf103", "RISCV:LE:32:default"},
};

class Uf2 final : public FileSystem {
 public:
  explicit Uf2(std::shared_ptr<const Source> src) : src_(std::move(src)) {}

  void parse(const Context &ctx) {
    format_ = "uf2";
    const std::uint64_t blocks = src_->size() / 512;
    if (blocks > (1u << 22)) throw LimitError("a UF2 file over 2 GiB");
    // Per family (or file name): address -> 476-byte payloads.
    struct Chunk {
      std::uint64_t address;
      std::uint64_t file_offset;  // of the payload
      std::uint32_t size;
    };
    std::map<std::string, std::vector<Chunk>> groups;
    std::map<std::string, std::string> languages;
    std::uint64_t skipped = 0;
    for (std::uint64_t i = 0; i < blocks; ++i) {
      ctx.check_cancelled();
      const auto b = src_->read_exact(i * 512, 512, "a UF2 block");
      if (le32(b.data()) != 0x0a324655 || le32(b.data() + 4) != 0x9e5d5157 || le32(b.data() + 508) != 0x0ab16f30) {
        ++skipped;
        continue;
      }
      const std::uint32_t flags = le32(b.data() + 8), addr = le32(b.data() + 12), size = le32(b.data() + 16);
      const std::uint32_t extra = le32(b.data() + 28);
      if (size > 476) {
        ++skipped;
        continue;
      }
      if (flags & 0x1) continue;  // not for the main flash
      std::string key;
      if (flags & 0x1000) {
        // A file container: the name follows the payload.
        std::string n(reinterpret_cast<const char *>(b.data() + 32 + size), 476 - size);
        n.resize(strnlen(n.c_str(), n.size()));
        key = "file:" + safe(n.empty() ? "file" : n);
      } else if (flags & 0x2000) {
        key = "family:" + hex32(extra);
        for (const Family &f : kFamilies)
          if (f.id == extra) {
            key = std::string("family:") + f.name;
            languages[key] = f.language;
          }
      } else {
        key = "family:unknown";
      }
      groups[key].push_back({addr, i * 512 + 32, size});
    }
    if (groups.empty()) throw Error("a UF2 file with no blocks for the main flash");
    if (skipped) warn(plural(skipped, "block was", "blocks were") + " not UF2 and skipped");
    TreeBuilder tree(*this, ctx.limits);
    for (auto &[key, chunks] : groups) {
      std::sort(chunks.begin(), chunks.end(), [](const Chunk &a, const Chunk &b) { return a.address < b.address; });
      const bool file = key.rfind("file:", 0) == 0;
      // Contiguous ranges (gaps under 64 KiB filled with 0xff) are one image each.
      std::size_t start = 0;
      while (start < chunks.size()) {
        std::size_t end = start + 1;
        std::uint64_t reach = chunks[start].address + chunks[start].size;
        while (end < chunks.size() && chunks[end].address <= reach + 65536 && chunks[end].address >= chunks[end - 1].address) {
          reach = std::max(reach, chunks[end].address + chunks[end].size);
          ++end;
        }
        const std::uint64_t base = file ? 0 : chunks[start].address;
        std::vector<Run> runs;
        std::vector<std::pair<std::uint64_t, std::uint64_t>> gaps;
        std::uint64_t at = file ? chunks[start].address : base;
        for (std::size_t k = start; k < end; ++k) {
          const Chunk &c = chunks[k];
          if (c.address < at) continue;  // a duplicate block
          if (c.address > at) gaps.push_back({at - base, c.address - at});
          runs.push_back({c.address - base, c.file_offset, c.size, false});
          at = c.address + c.size;
        }
        Entry e;
        e.kind = Kind::file;
        e.size = at - base;
        e.name = file ? key.substr(5) : key.substr(7) + "@" + hex32(base) + ".bin";
        e.loc0 = images_.size();
        if (!file) {
          e.load_address = base;
          if (auto l = languages.find(key); l != languages.end()) e.language = l->second;
        }
        images_.push_back({std::move(runs), std::move(gaps), e.size});
        tree.add_child(0, std::move(e));
        start = end;
      }
    }
    tree.finish();
    description_ = "UF2 firmware, " + plural(entries_.size() - 1, "image", "images");
  }

  std::shared_ptr<Source> open(std::uint32_t entry, const Context &ctx) const override {
    const Entry &e = entries_.at(entry);
    if (e.kind != Kind::file) throw Error("not a file");
    const Image &img = images_.at(e.loc0);
    // Gaps read as erased flash (0xff): materialize.
    Sink sink(ctx);
    auto mapped = mapped_source(src_, img.runs, img.size);
    std::vector<std::byte> buf(1 << 16);
    std::size_t g = 0;
    for (std::uint64_t off = 0; off < img.size;) {
      const std::size_t n = mapped->read(off, std::span(buf).first(static_cast<std::size_t>(std::min<std::uint64_t>(buf.size(), img.size - off))));
      for (; g < img.gaps.size() && img.gaps[g].first < off + n; ++g) {
        const auto &[gs, gl] = img.gaps[g];
        const std::uint64_t from = std::max(gs, off), to = std::min(gs + gl, off + n);
        if (from < to) std::memset(buf.data() + (from - off), 0xff, to - from);
        if (gs + gl > off + n) break;
      }
      sink.append(std::span(buf).first(n));
      off += n;
      if (n == 0) break;
    }
    return sink.finish();
  }

 private:
  struct Image {
    std::vector<Run> runs;
    std::vector<std::pair<std::uint64_t, std::uint64_t>> gaps;
    std::uint64_t size;
  };
  std::shared_ptr<const Source> src_;
  std::vector<Image> images_;
};

// ---- partition tables ----------------------------------------------------------

const char *mbr_type(std::uint8_t t) {
  switch (t) {
    case 0x01: return "FAT12";
    case 0x04: case 0x06: case 0x0e: return "FAT16";
    case 0x0b: case 0x0c: return "FAT32";
    case 0x07: return "NTFS/exFAT";
    case 0x82: return "Linux swap";
    case 0x83: return "Linux";
    case 0x8e: return "Linux LVM";
    case 0xa5: return "FreeBSD";
    case 0xee: return "GPT protective";
    case 0xef: return "EFI system";
    default: return nullptr;
  }
}

class Partitions final : public SliceFileSystem {
 public:
  using SliceFileSystem::SliceFileSystem;

  void parse(const Context &ctx) {
    format_ = "partitions";
    TreeBuilder tree(*this, ctx.limits);
    const std::uint64_t size = src_->size();
    std::string scheme;
    auto add = [&](std::string name, std::uint64_t first_lba, std::uint64_t sectors, std::uint64_t sector, std::string note) {
      const std::uint64_t off = first_lba * sector;
      if (off >= size) {
        warn(name + " starts past the end of the image");
        return;
      }
      std::uint64_t len = sectors * sector;
      if (len > size - off) {
        warn(name + " runs past the end of the image: cut");
        len = size - off;
      }
      Entry e;
      e.kind = Kind::file;
      e.name = name;
      e.loc0 = off;
      e.loc1 = len;
      e.size = len;
      e.stored_size = len;
      e.note = std::move(note);
      tree.add_child(0, std::move(e));
    };
    // GPT: at LBA 1 with 512-byte sectors, or 4096-byte ones.
    for (std::uint64_t sector : {512ull, 4096ull}) {
      if (size < sector * 2) continue;
      const auto hb = src_->read_exact(sector, 92, "the GPT header");
      if (std::string(reinterpret_cast<const char *>(hb.data()), 8) != "EFI PART") continue;
      Buf h(hb, "the GPT header");
      const std::uint64_t entries_lba = h.l64(72);
      const std::uint32_t count = h.l32(80), esize = h.l32(84);
      if (esize < 128 || esize > 4096 || count > 1024) throw Error("a GPT with a malformed partition array");
      const auto table = src_->read_exact(entries_lba * sector, static_cast<std::uint64_t>(count) * esize, "the GPT partitions");
      int n = 0;
      for (std::uint32_t i = 0; i < count; ++i) {
        const std::byte *e = table.data() + static_cast<std::size_t>(i) * esize;
        bool used = false;
        for (int k = 0; k < 16; ++k) used = used || e[k] != std::byte{0};
        if (!used) continue;
        const std::uint64_t first = le64(e + 32), last = le64(e + 40);
        if (last < first) continue;
        std::string label;
        for (int k = 0; k < 36; ++k) {
          const std::uint16_t ch = le16(e + 56 + 2 * k);
          if (!ch) break;
          if (ch < 0x80) label += static_cast<char>(ch);
          else label += '_';
        }
        ++n;
        add("p" + std::to_string(i + 1) + (label.empty() ? "" : "-" + safe(label)) + ".img", first, last - first + 1,
            sector, "");
      }
      scheme = "GPT, " + plural(n, "partition", "partitions");
      break;
    }
    if (scheme.empty()) {
      const auto mbr = src_->read_exact(0, 512, "the MBR");
      int n = 0;
      std::uint64_t extended = 0;
      for (int i = 0; i < 4; ++i) {
        const std::byte *p = mbr.data() + 446 + 16 * i;
        const auto type = static_cast<std::uint8_t>(p[4]);
        const std::uint32_t lba = le32(p + 8), count = le32(p + 12);
        if (type == 0 || count == 0) continue;
        if (type == 0x05 || type == 0x0f || type == 0x85) {
          extended = lba;
          continue;
        }
        const char *t = mbr_type(type);
        ++n;
        add("p" + std::to_string(i + 1) + ".img", lba, count, 512, std::string("type ") + hex32(type) + (t ? std::string(" (") + t + ")" : ""));
      }
      // Logical partitions: a chain of boot records inside the extended one.
      std::set<std::uint64_t> seen;
      std::uint64_t ebr = extended;
      for (int k = 5; ebr && k < 5 + 128; ++k) {
        if (!seen.insert(ebr).second) {
          warn("the logical partitions' chain loops");
          break;
        }
        const auto b = src_->read_exact(ebr * 512, 512, "an extended boot record");
        if (static_cast<std::uint8_t>(b[510]) != 0x55 || static_cast<std::uint8_t>(b[511]) != 0xaa) break;
        const std::byte *p1 = b.data() + 446, *p2 = b.data() + 462;
        const auto type = static_cast<std::uint8_t>(p1[4]);
        if (type && le32(p1 + 12)) {
          const char *t = mbr_type(type);
          ++n;
          add("p" + std::to_string(k) + ".img", ebr + le32(p1 + 8), le32(p1 + 12), 512,
              std::string("type ") + hex32(type) + (t ? std::string(" (") + t + ")" : ""));
        }
        ebr = le32(p2 + 12) ? extended + le32(p2 + 8) : 0;
      }
      scheme = "MBR, " + plural(n, "partition", "partitions");
    }
    tree.finish();
    description_ = "partitioned disk image (" + scheme + ")";
  }
};

}  // namespace

std::shared_ptr<FileSystem> open_uimage(std::shared_ptr<const Source> src, std::string_view, const Context &ctx) {
  auto fs = std::make_shared<UImage>(std::move(src));
  fs->parse(ctx);
  return fs;
}

std::shared_ptr<FileSystem> open_android_boot(std::shared_ptr<const Source> src, std::string_view, const Context &ctx) {
  auto fs = std::make_shared<AndroidBoot>(std::move(src));
  fs->parse(ctx);
  return fs;
}

std::shared_ptr<FileSystem> open_uf2(std::shared_ptr<const Source> src, std::string_view, const Context &ctx) {
  auto fs = std::make_shared<Uf2>(std::move(src));
  fs->parse(ctx);
  return fs;
}

std::shared_ptr<FileSystem> open_partitions(std::shared_ptr<const Source> src, std::string_view, const Context &ctx) {
  auto fs = std::make_shared<Partitions>(std::move(src));
  fs->parse(ctx);
  return fs;
}

}  // namespace revkit::container::detail
