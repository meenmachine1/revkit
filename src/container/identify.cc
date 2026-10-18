// Recognition by magic (never by name), the cheap "what is this file"
// guess for listings, and the format registry.
#include "asar.hh"
#include "bytecode.hh"
#include "exe.hh"
#include "formats.hh"
#include "jsexe.hh"
#include "luacarve.hh"
#include "pyinstaller.hh"

#include <zlib.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <map>
#include <optional>

namespace revkit::container {

using namespace detail;

namespace {

bool at(std::span<const std::byte> b, std::size_t off, std::string_view magic) {
  return b.size() >= off + magic.size() && std::memcmp(b.data() + off, magic.data(), magic.size()) == 0;
}

std::uint32_t octal(std::span<const std::byte> b, std::size_t off, std::size_t n, bool &ok) {
  std::uint32_t v = 0;
  bool digits = false;
  for (std::size_t i = off; i < off + n && i < b.size(); ++i) {
    const char c = static_cast<char>(b[i]);
    if (c == 0 || c == ' ') {
      if (digits) break;
      continue;
    }
    if (c < '0' || c > '7') {
      ok = false;
      return 0;
    }
    v = v * 8 + static_cast<std::uint32_t>(c - '0');
    digits = true;
  }
  ok = ok && digits;
  return v;
}

// A tar header block: the "ustar" magic, or (old v7 archives) a checksum
// that adds up.
bool tar_header(std::span<const std::byte> b) {
  if (b.size() < 512) return false;
  if (at(b, 257, "ustar")) return true;
  bool ok = true;
  const std::uint32_t sum = octal(b, 148, 8, ok);
  if (!ok || static_cast<char>(b[0]) == 0) return false;
  std::uint32_t mine = 0;
  for (std::size_t i = 0; i < 512; ++i) mine += (i >= 148 && i < 156) ? ' ' : static_cast<std::uint8_t>(b[i]);
  return sum == mine;
}

bool lzma_alone(std::span<const std::byte> b, std::uint64_t size) {
  if (b.size() < 13 || size < 18) return false;
  const auto props = static_cast<std::uint8_t>(b[0]);
  if (props >= 225) return false;
  // Every encoder writes lc=3 lp=0 pb=2 unless told otherwise; accept
  // the common ones only, as nothing else marks the format.
  if (props != 0x5d && props != 0x5e && props != 0x6d && props != 0x2c) return false;
  const std::uint32_t dict = le32(b.data() + 1);
  bool pow2ish = false;
  for (int k = 12; k <= 30 && !pow2ish; ++k)
    pow2ish = dict == (1u << k) || dict == (1u << k) + (1u << (k - 1));
  if (!pow2ish) return false;
  const std::uint64_t usize = le64(b.data() + 5);
  return usize == UINT64_MAX || usize < (1ull << 40);
}

bool uimage_header(std::span<const std::byte> b) {
  if (b.size() < 64 || be32(b.data()) != 0x27051956u) return false;
  std::array<std::byte, 64> h;
  std::memcpy(h.data(), b.data(), 64);
  const std::uint32_t want = be32(h.data() + 4);
  std::memset(h.data() + 4, 0, 4);
  return crc32_ieee(h) == want;
}

bool fat_boot(std::span<const std::byte> b) {
  if (b.size() < 512 || static_cast<std::uint8_t>(b[510]) != 0x55 || static_cast<std::uint8_t>(b[511]) != 0xaa)
    return false;
  const auto j = static_cast<std::uint8_t>(b[0]);
  if (j != 0xeb && j != 0xe9) return false;
  const std::uint16_t bps = le16(b.data() + 11);
  const auto spc = static_cast<std::uint8_t>(b[13]);
  const std::uint16_t reserved = le16(b.data() + 14);
  const auto fats = static_cast<std::uint8_t>(b[16]);
  if (bps != 512 && bps != 1024 && bps != 2048 && bps != 4096) return false;
  if (spc == 0 || (spc & (spc - 1))) return false;
  if (reserved == 0 || fats == 0 || fats > 4) return false;
  return at(b, 54, "FAT") || at(b, 82, "FAT32") || le16(b.data() + 22) != 0 || le32(b.data() + 36) != 0;
}

bool mbr(std::span<const std::byte> b, std::uint64_t size) {
  if (b.size() < 512 || static_cast<std::uint8_t>(b[510]) != 0x55 || static_cast<std::uint8_t>(b[511]) != 0xaa)
    return false;
  if (fat_boot(b)) return false;
  int used = 0;
  for (int i = 0; i < 4; ++i) {
    const std::byte *p = b.data() + 446 + 16 * i;
    const auto boot = static_cast<std::uint8_t>(p[0]), type = static_cast<std::uint8_t>(p[4]);
    if (boot != 0 && boot != 0x80) return false;
    const std::uint32_t lba = le32(p + 8), count = le32(p + 12);
    if (type == 0) continue;
    if (count == 0 || lba == 0 || (std::uint64_t{lba} + count) * 512 > size + (1ull << 20)) return false;
    ++used;
  }
  return used > 0;
}

std::string hexbyte(unsigned v) {
  char buf[8];
  std::snprintf(buf, sizeof buf, "0x%x", v);
  return buf;
}

struct Machine {
  std::uint16_t id;
  const char *name;
  const char *processor;  // Ghidra's processor name
};

constexpr Machine kElfMachines[] = {
    {2, "SPARC", "sparc"},       {3, "x86", "x86"},          {4, "68000", "68000"},     {8, "MIPS", "MIPS"},
    {10, "MIPS", "MIPS"},        {15, "PA-RISC", "pa-risc"}, {20, "PowerPC", "PowerPC"}, {21, "PowerPC64", "PowerPC"},
    {22, "S/390", ""},           {40, "ARM", "ARM"},         {42, "SuperH", "SuperH4"}, {43, "SPARC V9", "sparc"},
    {50, "IA-64", ""},           {62, "x86-64", "x86"},      {83, "AVR", "avr8"},       {87, "V850", "V850"},
    {92, "OpenRISC", ""},        {94, "Xtensa", "Xtensa"},   {105, "MSP430", "TI_MSP430"}, {106, "Blackfin", ""},
    {164, "Hexagon", "Hexagon"}, {183, "AArch64", "AARCH64"}, {189, "MicroBlaze", "MicroBlaze"},
    {243, "RISC-V", "RISCV"},    {247, "eBPF", "eBPF"},      {258, "LoongArch", "Loongarch"},
};

struct PeMachine {
  std::uint16_t id;
  const char *name;
  const char *processor;
};
constexpr PeMachine kPeMachines[] = {
    {0x14c, "x86", "x86:LE:32"},     {0x8664, "x86-64", "x86:LE:64"}, {0x1c0, "ARM", "ARM:LE:32"},
    {0x1c2, "Thumb", "ARM:LE:32"},   {0x1c4, "ARMv7", "ARM:LE:32"},   {0xaa64, "AArch64", "AARCH64:LE:64"},
    {0x200, "IA-64", ""},            {0x166, "MIPS", "MIPS:LE:32"},   {0x1f0, "PowerPC", "PowerPC:LE:32"},
};

bool text_like(std::span<const std::byte> b) {
  if (b.empty()) return false;
  std::size_t printable = 0;
  for (std::byte x : b) {
    const auto c = static_cast<std::uint8_t>(x);
    if (c == 0) return false;
    if (c >= 0x20 || c == '\n' || c == '\r' || c == '\t' || c == '\f') ++printable;
  }
  return printable * 100 >= b.size() * 97;
}

bool hex_line(std::span<const std::byte> b, char lead) {
  if (b.empty() || static_cast<char>(b[0]) != lead) return false;
  std::size_t i = 1, digits = 0;
  if (lead == 'S') {
    if (b.size() < 2 || static_cast<char>(b[1]) < '0' || static_cast<char>(b[1]) > '9') return false;
    i = 2;
  }
  for (; i < b.size(); ++i) {
    const char c = static_cast<char>(b[i]);
    if (c == '\r' || c == '\n') break;
    if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    ++digits;
  }
  return digits >= 8 && digits % 2 == 0;
}

const std::map<std::string, std::string> &format_kinds() {
  static const std::map<std::string, std::string> m = {
      {"zip", "zip archive"},          {"tar", "tar archive"},
      {"cpio", "cpio archive"},        {"ar", "ar archive"},
      {"iso9660", "ISO 9660 image"},   {"gzip", "gzip compressed"},
      {"bzip2", "bzip2 compressed"},   {"xz", "xz compressed"},
      {"lzma", "lzma compressed"},     {"zstd", "zstd compressed"},
      {"lz4", "lz4 compressed"},       {"squashfs", "squashfs file system"},
      {"ext", "ext2/3/4 file system"}, {"cramfs", "cramfs file system"},
      {"fat", "FAT file system"},      {"uimage", "U-Boot image"},
      {"android-boot", "Android boot image"}, {"uf2", "UF2 firmware"},
      {"partitions", "partitioned disk image"},
      {"asar", "Electron asar archive"},  {"pyinstaller", "PyInstaller archive"},
      {"pyz", "PyInstaller PYZ archive"}, {"lua-chunks", "Lua chunks"},
      {"node-sea", "Node.js single executable"}, {"pkg", "pkg executable"},
      {"nexe", "nexe executable"},        {"bun", "Bun executable"},
  };
  return m;
}

}  // namespace

std::uint32_t detail::crc32_ieee(std::span<const std::byte> data, std::uint32_t crc) {
  return static_cast<std::uint32_t>(::crc32(crc, reinterpret_cast<const Bytef *>(data.data()),
                                            static_cast<uInt>(data.size())));
}

std::string identify(const Source &src) {
  const std::vector<std::byte> h = src.head(kIdentifyBytes);
  std::string f = identify_head(h, src.size());
  if (f.empty()) f = identify_payload(src);
  return f;
}

// A zip appended to the file (py2exe's library, cx_Freeze's and
// self-extractors' archives): an end record in the last 64 KiB whose
// central directory, shifted by the prefix, lies in the file.
static bool appended_zip(const Source &src) {
  const std::uint64_t size = src.size();
  if (size < 22) return false;
  const std::uint64_t tail = std::min<std::uint64_t>(size, 65557);
  const auto t = src.read_exact(size - tail, tail, "the end of the file");
  for (std::size_t i = t.size() - 22 + 1; i-- > 0;) {
    if (le32(t.data() + i) != 0x06054b50) continue;
    const std::uint16_t comment = le16(t.data() + i + 20);
    if (i + 22 + comment != t.size()) continue;
    const std::uint64_t eocd = size - tail + i;
    const std::uint64_t entries = le16(t.data() + i + 10), cd_size = le32(t.data() + i + 12);
    if (entries == 0 || cd_size == 0 || cd_size > eocd) return false;
    // The first central directory record must be one.
    const auto c = src.read_exact(eocd - cd_size, 4, "a zip central directory");
    return le32(c.data()) == 0x02014b50;
  }
  return false;
}

std::string identify_payload(const Source &src, const std::function<bool()> &cancelled) {
  try {
    const ExeFormat exe = exe_format(src);
    if (exe != ExeFormat::none) {
      // Packed executables, most specific first.
      if (pyinstaller_payload(src)) return "pyinstaller";
      if (node_sea_payload(src)) return "node-sea";
      if (pkg_payload(src)) return "pkg";
      if (nexe_payload(src)) return "nexe";
      if (bun_payload(src)) return "bun";
      if (appended_zip(src)) return "zip";
      return "";
    }
    // Data with Lua chunks in it; not a chunk (or other bytecode) itself.
    const auto h = src.head(4096);
    if (bytecode_guess(h, src.size())) return "";
    if (lua_chunks_payload(src, cancelled)) return "lua-chunks";
  } catch (const Error &) {
  }
  return "";
}

std::string identify_head(std::span<const std::byte> b, std::uint64_t size) {
  if (at(b, 0, "PK\x03\x04") || at(b, 0, "PK\x05\x06")) return "zip";
  if (at(b, 0, "\x1f\x8b\x08")) return "gzip";
  if (at(b, 0, "BZh") && b.size() >= 10 && static_cast<char>(b[3]) >= '1' && static_cast<char>(b[3]) <= '9' &&
      (at(b, 4, "\x31\x41\x59\x26\x53\x59") || at(b, 4, "\x17\x72\x45\x38\x50\x90")))
    return "bzip2";
  if (at(b, 0, std::string_view("\xfd" "7zXZ\0", 6))) return "xz";
  if (at(b, 0, "\x28\xb5\x2f\xfd")) return "zstd";
  if (at(b, 0, "\x04\x22\x4d\x18") || at(b, 0, "\x02\x21\x4c\x18")) return "lz4";
  if (at(b, 0, "hsqs") || at(b, 0, "sqsh")) return "squashfs";
  if (at(b, 0, "070701") || at(b, 0, "070702") || at(b, 0, "070707") || at(b, 0, "\xc7\x71") ||
      at(b, 0, "\x71\xc7"))
    return "cpio";
  if (at(b, 0, "!<arch>\n")) return "ar";
  if (at(b, 0, "\x45\x3d\xcd\x28") || at(b, 0, "\x28\xcd\x3d\x45")) return "cramfs";
  if (b.size() >= 516 && (at(b, 512, "\x45\x3d\xcd\x28") || at(b, 512, "\x28\xcd\x3d\x45"))) return "cramfs";
  if (at(b, 0, "ANDROID!")) return "android-boot";
  if (at(b, 0, "UF2\n") && at(b, 4, "\x57\x51\x5d\x9e") && b.size() >= 512 && at(b, 508, "\x30\x6f\xb1\x0a"))
    return "uf2";
  if (uimage_header(b)) return "uimage";
  if (tar_header(b)) return "tar";
  if (b.size() >= 1082 && le16(b.data() + 1080) == 0xef53) {
    // The superblock's log block size and inode counts must be sane.
    const std::uint32_t log = le32(b.data() + 1024 + 24);
    if (log <= 6 && le32(b.data() + 1024 + 0) != 0 && le32(b.data() + 1024 + 40) != 0) return "ext";
  }
  if (at(b, 32769, "CD001")) return "iso9660";
  if (fat_boot(b)) return "fat";
  if (b.size() >= 512 + 8 && at(b, 512, "EFI PART")) return "partitions";
  if (mbr(b, size)) return "partitions";
  if (lzma_alone(b, size)) return "lzma";
  if (asar_header(b, size)) return "asar";
  if (pyz_header(b)) return "pyz";
  return "";
}

// A Mach-O CPU's name as lipo spells it, and its processor as Ghidra's
// language ids start ("AARCH64:LE:64").
static std::pair<std::string, std::string> macho_cpu(std::uint32_t cpu, std::uint32_t sub) {
  sub &= 0x00ffffff;
  switch (cpu) {
    case 7: return {"i386", "x86:LE:32"};
    case 0x01000007: return {sub == 8 ? "x86_64h" : "x86_64", "x86:LE:64"};
    case 0x0100000c: return {sub == 2 ? "arm64e" : "arm64", "AARCH64:LE:64"};
    case 0x0200000c: return {"arm64_32", "AARCH64:LE:32"};
    case 12: return {sub == 9 ? "armv7" : sub == 11 ? "armv7s" : sub == 12 ? "armv7k" : "arm", "ARM:LE:32"};
    case 18: return {"ppc", "PowerPC:BE:32"};
    case 0x01000012: return {"ppc64", "PowerPC:BE:64"};
    default: return {"cpu " + std::to_string(cpu), ""};
  }
}

static std::optional<Guess> macho_guess(std::span<const std::byte> b) {
  if (b.size() < 28) return std::nullopt;
  const std::uint32_t m = le32(b.data());
  static const char *types[] = {"", "object", "executable", "fixed VM library", "core", "preload", "dylib",
                                "dynamic linker", "bundle", "dylib stub", "dSYM", "kext", "fileset"};
  if (m == 0xfeedface || m == 0xfeedfacf || m == 0xcefaedfe || m == 0xcffaedfe) {
    const bool little = m == 0xfeedface || m == 0xfeedfacf, wide = m == 0xfeedfacf || m == 0xcffaedfe;
    const std::uint32_t cpu = little ? le32(b.data() + 4) : be32(b.data() + 4);
    const std::uint32_t sub = little ? le32(b.data() + 8) : be32(b.data() + 8);
    const std::uint32_t type = little ? le32(b.data() + 12) : be32(b.data() + 12);
    Guess g;
    g.kind = "macho";
    g.format = "macho";
    auto [arch, processor] = macho_cpu(cpu, sub);
    g.processor = processor;
    g.description = std::string("Mach-O ") + (wide ? "64" : "32") + "-bit " + arch +
                    (type >= 1 && type < std::size(types) ? std::string(" ") + types[type] : std::string());
    return g;
  }
  if (be32(b.data()) == 0xcafebabe || be32(b.data()) == 0xcafebabf) {
    const bool wide = be32(b.data()) == 0xcafebabf;
    const std::uint32_t n = be32(b.data() + 4);
    const std::size_t entry = wide ? 32 : 20;
    if (n == 0 || n > 64 || b.size() < 8 + n * entry) return std::nullopt;
    std::string archs;
    for (std::uint32_t i = 0; i < n; ++i) {
      const std::byte *e = b.data() + 8 + i * entry;
      auto [arch, processor] = macho_cpu(be32(e), be32(e + 4));
      // A slice of a known CPU at an aligned offset past the header.
      const std::uint64_t off = wide ? (std::uint64_t{be32(e + 8)} << 32 | be32(e + 12)) : be32(e + 8);
      const std::uint32_t align = be32(e + (wide ? 24 : 16));
      if (processor.empty() || align > 16 || off < 8 + n * entry || off % (std::uint64_t{1} << align) != 0)
        return std::nullopt;
      archs += (i ? ", " : "") + arch;
    }
    Guess g;
    g.kind = "macho";
    g.format = "macho";
    g.description = "Mach-O universal (" + archs + ")";
    return g;
  }
  return std::nullopt;
}

Guess guess(std::span<const std::byte> b, std::uint64_t size, std::string_view container_format) {
  Guess g;
  if (size == 0) {
    g.kind = "empty";
    g.description = "empty";
    return g;
  }
  if (!container_format.empty()) {
    g.kind = "container";
    g.format = std::string(container_format);
    auto it = format_kinds().find(g.format);
    g.description = it == format_kinds().end() ? g.format : it->second;
    if (g.format == "zip") {
      g.content_kind = zip_content_kind(b);
      if (g.content_kind == "apk") g.description += " (Android package)";
      else if (g.content_kind == "jar") g.description += " (Java archive)";
    }
    if (g.format == "uimage" && b.size() >= 64) {
      static const std::map<unsigned, const char *> arch = {
          {1, "Alpha"}, {2, "ARM"},  {3, "x86"},   {4, "IA-64"}, {5, "MIPS"},   {6, "MIPS64"},  {7, "PowerPC"},
          {8, "S/390"}, {9, "SuperH"}, {10, "SPARC"}, {11, "SPARC64"}, {12, "68000"}, {14, "MicroBlaze"},
          {15, "Nios II"}, {16, "Blackfin"}, {17, "AVR32"}, {20, "x86-64"}, {21, "Xtensa"}, {22, "AArch64"},
          {26, "RISC-V"}};
      auto a = arch.find(static_cast<std::uint8_t>(b[29]));
      if (a != arch.end()) {
        g.description += ", " + std::string(a->second);
        g.processor = a->second;
      }
      g.description += ", \"" + display_name(Buf(b).cstr(32, 32)) + "\"";
    }
    return g;
  }
  if (at(b, 0, "\x7f" "ELF") && b.size() >= 20) {
    g.kind = "elf";
    g.format = "elf";
    const bool is64 = static_cast<std::uint8_t>(b[4]) == 2, be = static_cast<std::uint8_t>(b[5]) == 2;
    const std::uint16_t machine = be ? be16(b.data() + 18) : le16(b.data() + 18);
    const std::uint16_t type = be ? be16(b.data() + 16) : le16(b.data() + 16);
    std::string mname = "machine " + std::to_string(machine);
    for (const Machine &m : kElfMachines)
      if (m.id == machine) {
        mname = m.name;
        if (*m.processor)
          g.processor = std::string(m.processor) + (be ? ":BE:" : ":LE:") + (is64 ? "64" : "32");
      }
    const char *types[] = {"", "relocatable", "executable", "shared object", "core dump"};
    g.description = "ELF " + std::string(is64 ? "64" : "32") + "-bit " + (be ? "BE " : "LE ") + mname +
                    (type >= 1 && type <= 4 ? std::string(" ") + types[type] : std::string());
    return g;
  }
  if (at(b, 0, "MZ") && b.size() >= 64) {
    const std::uint32_t pe = le32(b.data() + 0x3c);
    if (pe + 24 <= b.size() && at(b, pe, std::string_view("PE\0\0", 4))) {
      g.kind = "pe";
      g.format = "pe";
      const std::uint16_t machine = le16(b.data() + pe + 4), chars = le16(b.data() + pe + 22);
      std::string mname = "machine " + hexbyte(machine);
      for (const PeMachine &m : kPeMachines)
        if (m.id == machine) {
          mname = m.name;
          g.processor = m.processor;
        }
      g.description = "PE " + mname + ((chars & 0x2000) ? " DLL" : " executable");
      if (auto d = dotnet_head(b, pe)) {
        g.description += d->description;
        g.content_kind = d->content_kind;
      }
      return g;
    }
    g.kind = "data";
    g.format = "mz";
    g.description = "MS-DOS executable";
    return g;
  }
  // Mach-O, thin or universal (the latter only when its header lists
  // plausible slices: a Java class file shares 0xcafebabe).
  if (auto m = macho_guess(b); m) return *m;
  // Bytecode and compiled scripts (docs/bytecode-lifting.md): a .pyc, Lua
  // and LuaJIT chunks, Java classes (0xcafebabe that isn't a universal
  // Mach-O), DEX, WebAssembly, Hermes, V8 code caches, ...
  if (auto bc = bytecode_guess(b, size); bc) return *bc;
  struct Simple {
    std::string_view magic;
    const char *format, *description, *kind;
  };
  static const Simple simple[] = {
      {"\xd0\x0d\xfe\xed", "dtb", "device tree blob", "data"},
      {"\x89PNG", "png", "PNG image", "data"},
      {"\xff\xd8\xff", "jpeg", "JPEG image", "data"},
      {"%PDF", "pdf", "PDF document", "data"},
      {"SQLite format 3", "sqlite", "SQLite database", "data"},
      {"\x7f" "ELF", "elf", "ELF (truncated)", "data"},
  };
  for (const Simple &s : simple)
    if (s.magic.size() <= b.size() && std::memcmp(b.data(), s.magic.data(), s.magic.size()) == 0) {
      g.kind = s.kind;
      g.format = s.format;
      g.description = s.description;
      return g;
    }
  if (hex_line(b, ':')) {
    g.kind = "raw";
    g.format = "ihex";
    g.description = "Intel HEX";
    return g;
  }
  if (hex_line(b, 'S')) {
    g.kind = "raw";
    g.format = "srec";
    g.description = "Motorola S-record";
    return g;
  }
  if (text_like(b.first(std::min<std::size_t>(b.size(), 4096)))) {
    g.kind = "text";
    g.format = "text";
    if (at(b, 0, "#!")) {
      std::size_t e = 2;
      while (e < b.size() && e < 80 && static_cast<char>(b[e]) != '\n') ++e;
      const std::string_view line(reinterpret_cast<const char *>(b.data()), e);
      g.description = "script (" + display_name(line) + ")";
      // The interpreter the #! line names: a script a decompiler provider
      // would take as source.
      auto runs = [&](std::string_view interp) {
        for (std::size_t i = line.find(interp); i != std::string_view::npos; i = line.find(interp, i + 1)) {
          const bool start = i > 0 && (line[i - 1] == '/' || line[i - 1] == ' ');
          const std::size_t end = i + interp.size();
          const bool stop = end == line.size() || line[end] == ' ' || line[end] == '\r' ||
                            (line[end] >= '0' && line[end] <= '9') || line[end] == '.';
          if (start && stop) return true;
        }
        return false;
      };
      if (runs("node") || runs("nodejs") || runs("deno") || runs("bun")) g.content_kind = "js-source";
      else if (runs("python") || runs("python2") || runs("python3")) g.content_kind = "python-source";
      else if (runs("lua") || runs("luajit")) g.content_kind = "lua-source";
    } else {
      g.description = "text";
    }
    return g;
  }
  g.kind = "raw";
  g.format = "data";
  g.description = "data";
  return g;
}

std::shared_ptr<FileSystem> open_format(const std::string &format, std::shared_ptr<const Source> src,
                                        std::string_view name, const Context &ctx) {
  static const std::map<std::string, Opener, std::less<>> openers = {
      {"zip", open_zip},          {"tar", open_tar},         {"cpio", open_cpio},
      {"ar", open_ar},            {"iso9660", open_iso9660}, {"squashfs", open_squashfs},
      {"ext", open_ext},          {"cramfs", open_cramfs},   {"fat", open_fat},
      {"uimage", open_uimage},    {"android-boot", open_android_boot}, {"uf2", open_uf2},
      {"partitions", open_partitions},
      {"asar", open_asar},        {"pyinstaller", open_pyinstaller}, {"pyz", open_pyz},
      {"lua-chunks", open_lua_chunks}, {"node-sea", open_node_sea}, {"pkg", open_pkg},
      {"nexe", open_nexe},        {"bun", open_bun},
  };
  static const std::map<std::string, Codec, std::less<>> codecs = {
      {"gzip", Codec::gzip}, {"bzip2", Codec::bzip2}, {"xz", Codec::xz},
      {"lzma", Codec::lzma_alone}, {"zstd", Codec::zstd}, {"lz4", Codec::lz4_frame},
  };
  if (auto it = openers.find(format); it != openers.end()) return it->second(std::move(src), name, ctx);
  if (auto it = codecs.find(format); it != codecs.end()) return open_compressed(it->second, std::move(src), name, ctx);
  throw Error("unknown container format \"" + format + "\"");
}

std::shared_ptr<FileSystem> open_container(std::shared_ptr<const Source> src, std::string_view name,
                                           const Context &ctx) {
  const std::string f = identify(*src);
  if (f.empty()) return nullptr;
  return open_format(f, std::move(src), name, ctx);
}

std::vector<std::string> formats() {
  return {"zip", "tar", "cpio", "ar", "iso9660", "gzip", "bzip2", "xz", "lzma", "zstd", "lz4", "squashfs",
          "ext", "cramfs", "fat", "uimage", "android-boot", "uf2", "partitions", "asar", "pyinstaller", "pyz",
          "lua-chunks", "node-sea", "pkg", "nexe", "bun"};
}

}  // namespace revkit::container
