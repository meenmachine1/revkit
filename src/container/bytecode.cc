// Bytecode and compiled scripts by their headers (docs/bytecode-lifting.md,
// docs/filesystems.md "Content kinds"). The facts are the formats' own:
// CPython's magic numbers (Lib/importlib/_bootstrap_external.py and
// Include/internal/pycore_magic_number.h, PSF licence: numbers only), Lua's
// ldump.c and LuaJIT's lj_bcdump.h (MIT), the JVM class file and DEX
// headers, WebAssembly's preamble, Hermes's BytecodeFileFormat.h (MIT),
// V8's code-serializer.h (BSD-3-Clause), ECMA-335 for the CLR header.
#include "bytecode.hh"

#include "formats.hh"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <functional>

namespace revkit::container::detail {

namespace {

bool at(std::span<const std::byte> b, std::size_t off, std::string_view magic) {
  return b.size() >= off + magic.size() && std::memcmp(b.data() + off, magic.data(), magic.size()) == 0;
}

std::uint8_t u8(std::span<const std::byte> b, std::size_t off) { return static_cast<std::uint8_t>(b[off]); }

// CPython magic numbers by version: the first and last of each range
// (development builds included) and the release's own. From 3.11, 3.n
// takes 2900 + 50n to 2949 + 50n.
struct PyRange {
  std::uint16_t first, last, release;
  int major, minor;
};
constexpr PyRange kPyRanges[] = {
    {50823, 50823, 50823, 2, 0}, {60202, 60202, 60202, 2, 1}, {60717, 60717, 60717, 2, 2},
    {62011, 62021, 62021, 2, 3}, {62041, 62061, 62061, 2, 4}, {62071, 62131, 62131, 2, 5},
    {62151, 62161, 62161, 2, 6}, {62171, 62211, 62211, 2, 7}, {3000, 3139, 3131, 3, 0},
    {3140, 3159, 3151, 3, 1},    {3160, 3189, 3180, 3, 2},    {3190, 3249, 3230, 3, 3},
    {3250, 3319, 3310, 3, 4},    {3320, 3359, 3351, 3, 5},    {3360, 3389, 3379, 3, 6},
    {3390, 3399, 3394, 3, 7},    {3400, 3419, 3413, 3, 8},    {3420, 3429, 3425, 3, 9},
    {3430, 3449, 3439, 3, 10},   {3450, 3499, 3495, 3, 11},   {3500, 3549, 3531, 3, 12},
    {3550, 3599, 3571, 3, 13},   {3600, 3649, 3627, 3, 14},   {3650, 3699, 3666, 3, 15},  {3700, 3749, 0, 3, 16},
};

std::uint16_t r16le(std::span<const std::byte> b, std::size_t off) { return le16(b.data() + off); }
std::uint32_t r32le(std::span<const std::byte> b, std::size_t off) { return le32(b.data() + off); }
std::uint32_t r32be(std::span<const std::byte> b, std::size_t off) { return be32(b.data() + off); }

std::optional<Guess> pyc_guess(std::span<const std::byte> b) {
  if (b.size() < 16 || !at(b, 2, "\r\n")) return std::nullopt;
  const std::uint16_t magic = r16le(b, 0);
  auto v = pyc_version(magic);
  if (!v) return std::nullopt;
  const std::size_t h = pyc_header_size(*v);
  // The marshalled code object: TYPE_CODE ('c'), with FLAG_REF from 3.4.
  if (b.size() <= h || (u8(b, h) & 0x7f) != 'c') return std::nullopt;
  Guess g;
  g.kind = "bytecode";
  g.format = "pyc";
  g.content_kind = "pyc:" + v->str();
  g.description = "Python " + v->str() + " bytecode (magic " + std::to_string(magic) + ")";
  if (v->major == 3 && v->minor >= 7 && (r32le(b, 4) & 1)) g.description += ", hash-based";
  return g;
}

std::string java_version(unsigned major) {
  if (major >= 49) return std::to_string(major - 44);
  return "1." + std::to_string(major - 44);
}

std::optional<Guess> class_guess(std::span<const std::byte> b) {
  if (b.size() < 10 || r32be(b, 0) != 0xcafebabe) return std::nullopt;
  const unsigned minor = be16(b.data() + 4), major = be16(b.data() + 6);
  const unsigned pool = be16(b.data() + 8);
  if (major < 45 || major > 90 || pool == 0) return std::nullopt;
  Guess g;
  g.kind = "bytecode";
  g.format = "class";
  g.content_kind = "java-class:" + java_version(major);
  g.description = "Java class (Java " + java_version(major) + ", class file " + std::to_string(major) + "." +
                  std::to_string(minor) + ")";
  return g;
}

std::optional<Guess> dex_guess(std::span<const std::byte> b) {
  if (b.size() < 8 || !(at(b, 0, "dex\n") || at(b, 0, "dey\n")) || u8(b, 7) != 0) return std::nullopt;
  for (int i = 4; i < 7; ++i)
    if (u8(b, i) < '0' || u8(b, i) > '9') return std::nullopt;
  const std::string ver(reinterpret_cast<const char *>(b.data() + 4), 3);
  Guess g;
  g.kind = "bytecode";
  const bool odex = at(b, 0, "dey\n");
  g.format = odex ? "odex" : "dex";
  g.content_kind = (odex ? "odex:" : "dex:") + ver;
  g.description = std::string(odex ? "Android optimized DEX " : "Android DEX ") + ver;
  return g;
}

std::optional<Guess> wasm_guess(std::span<const std::byte> b) {
  if (b.size() < 8 || !at(b, 0, std::string_view("\0asm", 4))) return std::nullopt;
  const std::uint32_t version = r32le(b, 4);
  Guess g;
  g.kind = "bytecode";
  g.format = "wasm";
  if (version == 1) {
    g.content_kind = "wasm";
    g.description = "WebAssembly module (version 1)";
  } else if ((version & 0xffff) == 0x0d && (version >> 16) == 1) {
    g.content_kind = "wasm-component";
    g.description = "WebAssembly component";
  } else {
    g.content_kind = "wasm";
    g.description = "WebAssembly module (version " + std::to_string(version) + ")";
  }
  return g;
}

// Ethereum Virtual Machine bytecode as solc writes it (docs/evm.md): the
// free-memory pointer set first, PUSH1 0x80 PUSH1 0x40 MSTORE (0x60 before
// solc 0.4.22), as bytes or as hex text ("0x6080604052...").
std::optional<Guess> evm_guess(std::span<const std::byte> b) {
  auto prologue = [](std::string_view hex) {
    return hex.starts_with("6080604052") || hex.starts_with("6060604052");
  };
  Guess g;
  g.kind = "bytecode";
  g.format = "evm";
  g.content_kind = "evm";
  if (b.size() >= 5 && u8(b, 0) == 0x60 && (u8(b, 1) == 0x80 || u8(b, 1) == 0x60) && u8(b, 2) == 0x60 &&
      u8(b, 3) == 0x40 && u8(b, 4) == 0x52) {
    g.description = "EVM bytecode (solc)";
    return g;
  }
  std::string head;
  for (std::size_t i = 0; i < b.size() && head.size() < 12; ++i) head.push_back(static_cast<char>(std::tolower(u8(b, i))));
  if (head.starts_with("0x")) head.erase(0, 2);
  if (!prologue(head)) return std::nullopt;
  g.description = "EVM bytecode as hex text (solc)";
  return g;
}

// Hermes (React Native): BytecodeFileFormat.h's MAGIC, little-endian, then
// the bytecode version; DELTA_MAGIC (~MAGIC) for a delta bundle.
std::optional<Guess> hermes_guess(std::span<const std::byte> b) {
  if (b.size() < 12) return std::nullopt;
  const std::uint64_t m = le64(b.data());
  const bool delta = m == ~0x1F1903C103BC1FC6ull;
  if (m != 0x1F1903C103BC1FC6ull && !delta) return std::nullopt;
  const std::uint32_t version = r32le(b, 8);
  if (version == 0 || version > 1000) return std::nullopt;
  Guess g;
  g.kind = "bytecode";
  g.format = "hermes";
  g.content_kind = "hermes:" + std::to_string(version);
  g.description = std::string(delta ? "Hermes delta bytecode" : "Hermes bytecode") + " (version " +
                  std::to_string(version) + ")";
  return g;
}

// A V8 code cache (vm.Script's cachedData, bytenode's .jsc, pkg's compiled
// sources): SerializedCodeData's header, its magic 0xC0DE0000 ^ the
// external reference table's size, and a payload length that fills the
// file (24-byte header in older V8, 32 since the read-only snapshot
// checksum).
std::optional<Guess> v8_guess(std::span<const std::byte> b, std::uint64_t size) {
  if (b.size() < 32 || (r32le(b, 0) & 0xffff0000u) != 0xc0de0000u) return std::nullopt;
  const bool fits = (size >= 24 && r32le(b, 16) == size - 24) || (size >= 32 && r32le(b, 20) == size - 32);
  if (!fits) return std::nullopt;
  Guess g;
  g.kind = "bytecode";
  g.format = "v8-cache";
  g.content_kind = "v8-cache";
  char buf[16];
  std::snprintf(buf, sizeof buf, "%08x", r32le(b, 4));
  g.description = std::string("V8 code cache (version hash ") + buf + ")";
  return g;
}

std::optional<Guess> lua_guess(std::span<const std::byte> b) {
  auto h = lua_header(b, 0);
  if (!h) return std::nullopt;
  Guess g;
  g.kind = "bytecode";
  g.format = h->luajit ? "luajit" : "lua";
  g.content_kind = h->content_kind();
  g.description = h->description();
  return g;
}

std::optional<Guess> other_guess(std::span<const std::byte> b) {
  Guess g;
  g.kind = "bytecode";
  if (b.size() >= 12 && at(b, 0, "YARB")) {
    // RubyVM::InstructionSequence#to_binary: "YARB", major, minor (u32).
    const std::uint32_t major = r32le(b, 4), minor = r32le(b, 8);
    if (major < 2 || major > 9 || minor > 99) return std::nullopt;
    const std::string v = std::to_string(major) + "." + std::to_string(minor);
    g.format = "yarb";
    g.content_kind = "yarb:" + v;
    g.description = "Ruby " + v + " instruction sequence (YARB)";
    return g;
  }
  if (b.size() >= 8 && at(b, 0, std::string_view("OPCACHE", 7))) {
    g.format = "php-opcache";
    g.content_kind = "php-opcache";
    g.description = "PHP opcache file";
    return g;
  }
  if (b.size() >= 12 && at(b, 0, "FOR1") && at(b, 8, "BEAM")) {
    g.format = "beam";
    g.content_kind = "beam";
    g.description = "Erlang BEAM module";
    return g;
  }
  if (b.size() >= 8 && at(b, 0, "JRRY")) {
    g.format = "jerryscript";
    g.content_kind = "jerryscript:" + std::to_string(r32le(b, 4));
    g.description = "JerryScript snapshot (version " + std::to_string(r32le(b, 4)) + ")";
    return g;
  }
  return std::nullopt;
}

std::optional<std::uint64_t> uleb(std::span<const std::byte> b, std::size_t &p, unsigned max_bytes = 10) {
  std::uint64_t v = 0;
  for (unsigned shift = 0, n = 0; n < max_bytes; shift += 7, ++n) {
    if (p >= b.size()) return std::nullopt;
    const std::uint8_t c = u8(b, p++);
    if (shift < 64) v |= std::uint64_t{c & 0x7fu} << shift;
    if (!(c & 0x80)) return v;
  }
  return std::nullopt;
}

bool size_ok(int n) { return n == 1 || n == 2 || n == 4 || n == 8; }

}  // namespace

std::optional<PyVersion> pyc_version(std::uint16_t magic) {
  for (const PyRange &r : kPyRanges)
    if (magic >= r.first && magic <= r.last) return PyVersion{r.major, r.minor};
  return std::nullopt;
}

std::uint16_t pyc_release_magic(PyVersion v) {
  for (const PyRange &r : kPyRanges)
    if (r.major == v.major && r.minor == v.minor) return r.release;
  return 0;
}

std::size_t pyc_header_size(PyVersion v) {
  if (v.major < 3 || (v.major == 3 && v.minor < 3)) return 8;
  if (v.major == 3 && v.minor < 7) return 12;
  return 16;
}

std::vector<std::byte> pyc_header(std::uint16_t magic) {
  auto v = pyc_version(magic);
  std::vector<std::byte> h(v ? pyc_header_size(*v) : 16, std::byte{0});
  h[0] = static_cast<std::byte>(magic & 0xff);
  h[1] = static_cast<std::byte>(magic >> 8);
  h[2] = std::byte{'\r'};
  h[3] = std::byte{'\n'};
  return h;
}

std::string LuaHeader::content_kind() const {
  if (luajit) return version == 1 ? "luajit:2.0" : "luajit:2.1";
  return "lua:" + std::to_string(version >> 4) + "." + std::to_string(version & 0xf);
}

std::string LuaHeader::description() const {
  if (luajit) {
    std::string s = std::string("LuaJIT ") + (version == 1 ? "2.0" : "2.1") + " bytecode";
    std::string extra;
    if (luajit_flags & 1) extra += ", big-endian";
    if (luajit_flags & 2) extra += ", stripped";
    if (luajit_flags & 8) extra += ", two-slot frames (GC64)";
    return s + extra;
  }
  std::string s = "Lua " + std::to_string(version >> 4) + "." + std::to_string(version & 0xf) + " chunk";
  std::string sizes;
  if (version >= 0x53) {
    sizes = std::to_string(integer_size * 8) + "-bit integers, " + std::to_string(number_size * 8) + "-bit floats";
  } else {
    sizes = std::to_string(number_size * 8) + "-bit " + (integral ? "integer" : "float") + " numbers";
  }
  if (version <= 0x52) sizes += big_endian ? ", big-endian" : ", little-endian";
  return s + " (" + sizes + ")";
}

std::optional<LuaHeader> lua_header(std::span<const std::byte> b, std::size_t off) {
  if (off > b.size()) return std::nullopt;
  b = b.subspan(off);
  LuaHeader h;
  if (at(b, 0, "\x1bLJ")) {
    // LuaJIT (lj_bcdump.h): version 1 (2.0) or 2 (2.1), then the flags and,
    // unless stripped, the chunk's name.
    if (b.size() < 5) return std::nullopt;
    h.luajit = true;
    h.version = u8(b, 3);
    if (h.version != 1 && h.version != 2) return std::nullopt;
    std::size_t p = 4;
    auto flags = uleb(b, p, 5);
    if (!flags || *flags >= (h.version == 1 ? 8u : 32u)) return std::nullopt;  // 2.1 adds FR2, BITOP
    h.luajit_flags = static_cast<std::uint32_t>(*flags);
    h.big_endian = (*flags & 1) != 0;
    if (!(*flags & 2)) {
      auto len = uleb(b, p, 5);
      if (!len || *len > 4096 || p + *len > b.size()) return std::nullopt;
      p += *len;
    }
    h.size = p;
    return h;
  }
  if (!at(b, 0, "\x1bLua") || b.size() < 12) return std::nullopt;
  h.version = u8(b, 4);
  const std::uint8_t format = u8(b, 5);
  if (format != 0) return std::nullopt;  // the official format only
  static constexpr std::string_view kData("\x19\x93\r\n\x1a\n", 6);
  switch (h.version) {
    case 0x51:
    case 0x52: {
      const std::uint8_t endian = u8(b, 6);
      if (endian > 1) return std::nullopt;
      h.big_endian = endian == 0;
      h.int_size = u8(b, 7);
      h.size_t_size = u8(b, 8);
      h.instruction_size = u8(b, 9);
      h.number_size = u8(b, 10);
      const std::uint8_t integral = u8(b, 11);
      if (integral > 1) return std::nullopt;
      h.integral = integral == 1;
      h.size = 12;
      if (h.version == 0x52) {
        if (!at(b, 12, kData)) return std::nullopt;
        h.size = 18;
      }
      break;
    }
    case 0x53: {
      // LUAC_DATA, the sizes of int, size_t, Instruction, lua_Integer and
      // lua_Number, LUAC_INT (0x5678) and LUAC_NUM (370.5), as written.
      if (!at(b, 6, kData) || b.size() < 17) return std::nullopt;
      h.int_size = u8(b, 12);
      h.size_t_size = u8(b, 13);
      h.instruction_size = u8(b, 14);
      h.integer_size = u8(b, 15);
      h.number_size = u8(b, 16);
      h.size = 17 + h.integer_size + h.number_size;
      break;
    }
    case 0x54: {
      // LUAC_DATA, the sizes of Instruction, lua_Integer and lua_Number,
      // LUAC_INT and LUAC_NUM.
      if (!at(b, 6, kData) || b.size() < 15) return std::nullopt;
      h.instruction_size = u8(b, 12);
      h.integer_size = u8(b, 13);
      h.number_size = u8(b, 14);
      h.size = 15 + h.integer_size + h.number_size;
      break;
    }
    case 0x55: {
      // LUAC_DATA, then each of int, Instruction, lua_Integer and
      // lua_Number as its size and a sample value (-0x5678, 0x12345678,
      // -0x5678, -370.5) in the build's byte order.
      if (!at(b, 6, kData) || b.size() < 13) return std::nullopt;
      std::size_t p = 12;
      auto sample = [&](int &size, std::uint64_t want) {
        if (p >= b.size()) return false;
        size = u8(b, p++);
        if (size != 4 && size != 8) return false;
        if (p + static_cast<std::size_t>(size) > b.size()) return false;
        std::uint64_t vle = 0, vbe = 0;
        for (int i = 0; i < size; ++i) {
          vle |= std::uint64_t{u8(b, p + i)} << (8 * i);
          vbe = vbe << 8 | u8(b, p + i);
        }
        p += static_cast<std::size_t>(size);
        const std::uint64_t mask = size == 8 ? ~0ull : 0xffffffffull;
        if ((vle & mask) == (want & mask)) h.big_endian = false;
        else if ((vbe & mask) == (want & mask)) h.big_endian = true;
        else return false;
        return true;
      };
      if (!sample(h.int_size, static_cast<std::uint64_t>(-0x5678ll)) || !sample(h.instruction_size, 0x12345678) ||
          !sample(h.integer_size, static_cast<std::uint64_t>(-0x5678ll)))
        return std::nullopt;
      if (p >= b.size()) return std::nullopt;
      h.number_size = u8(b, p++);
      if (h.number_size != 4 && h.number_size != 8) return std::nullopt;
      h.size = p + h.number_size + 1;  // the sample float, the upvalue count
      h.size_t_size = 8;
      if (b.size() < h.size) return std::nullopt;
      return h;
    }
    default:
      return std::nullopt;
  }
  if (h.version != 0x54 && (!size_ok(h.int_size) || h.int_size < 2 || !size_ok(h.size_t_size) || h.size_t_size < 2))
    return std::nullopt;
  if (h.instruction_size != 4 && h.instruction_size != 8) return std::nullopt;
  if (h.number_size != 4 && h.number_size != 8 && !(h.version <= 0x52 && h.integral && size_ok(h.number_size)))
    return std::nullopt;
  if (h.version >= 0x53 && h.integer_size != 4 && h.integer_size != 8) return std::nullopt;
  if (h.version >= 0x53) {
    // LUAC_INT and LUAC_NUM in the build's byte order, which they tell:
    // the integer 0x5678 must read back in one of them.
    if (b.size() < h.size) return std::nullopt;
    const std::size_t ip = h.size - h.integer_size - h.number_size;
    std::uint64_t vle = 0, vbe = 0;
    for (int i = 0; i < h.integer_size; ++i) {
      vle |= std::uint64_t{u8(b, ip + i)} << (8 * i);
      vbe = vbe << 8 | u8(b, ip + i);
    }
    if (vle == 0x5678) h.big_endian = false;
    else if (vbe == 0x5678) h.big_endian = true;
    else return std::nullopt;
  }
  if (h.version >= 0x53) ++h.size;  // the main function's upvalue count
  if (b.size() < h.size) return std::nullopt;
  return h;
}

std::optional<Guess> bytecode_guess(std::span<const std::byte> b, std::uint64_t size) {
  if (auto g = pyc_guess(b)) return g;
  if (auto g = lua_guess(b)) return g;
  if (auto g = class_guess(b)) return g;
  if (auto g = dex_guess(b)) return g;
  if (auto g = wasm_guess(b)) return g;
  if (auto g = hermes_guess(b)) return g;
  if (auto g = evm_guess(b)) return g;
  if (auto g = v8_guess(b, size)) return g;
  if (auto g = other_guess(b)) return g;
  return std::nullopt;
}

std::optional<DotNetHead> dotnet_head(std::span<const std::byte> b, std::uint32_t pe) {
  try {
    Buf r(b, "PE headers");
    const std::uint64_t coff = std::uint64_t{pe} + 4;
    const std::uint16_t nsec = r.l16(coff + 2), opt_size = r.l16(coff + 16);
    const std::uint64_t opt = coff + 20;
    const std::uint16_t magic = r.l16(opt);
    const bool wide = magic == 0x20b;
    if (!wide && magic != 0x10b) return std::nullopt;
    const std::uint64_t dirs = opt + (wide ? 112 : 96);
    const std::uint32_t ndirs = r.l32(opt + (wide ? 108 : 92));
    if (ndirs <= 14 || dirs + 15 * 8 > opt + opt_size) return std::nullopt;
    const std::uint32_t clr = r.l32(dirs + 14 * 8), clr_size = r.l32(dirs + 14 * 8 + 4);
    if (clr == 0 || clr_size < 72) return std::nullopt;
    const std::uint64_t sections = opt + opt_size;
    auto offset_of = [&](std::uint32_t rva) -> std::optional<std::uint64_t> {
      for (std::uint16_t i = 0; i < std::min<std::uint16_t>(nsec, 96); ++i) {
        const std::uint64_t s = sections + i * 40ull;
        const std::uint32_t vsize = r.l32(s + 8), va = r.l32(s + 12), raw = r.l32(s + 16), ptr = r.l32(s + 20);
        if (rva >= va && rva - va < std::max(vsize, raw) && rva - va < raw) return std::uint64_t{ptr} + (rva - va);
      }
      return std::nullopt;
    };
    auto h = offset_of(clr);
    DotNetHead out;
    if (!h || *h + 72 > b.size()) {
      out.content_kind = "dotnet";
      out.description = ", .NET assembly";
      return out;
    }
    const std::uint32_t flags = r.l32(*h + 16);
    const bool il_only = flags & 1;
    out.content_kind = il_only ? "dotnet:il" : "dotnet:mixed";
    out.description = std::string(", .NET assembly (") + (il_only ? "IL-only" : "mixed-mode");
    if (auto m = offset_of(r.l32(*h + 8)); m && *m + 16 <= b.size() && r.l32(*m) == 0x424a5342) {
      const std::uint32_t vlen = r.l32(*m + 12);
      if (vlen > 0 && vlen <= 64 && *m + 16 + vlen <= b.size()) {
        std::string v = r.cstr(*m + 16, vlen);
        out.description += ", metadata " + display_name(v);
      }
    }
    out.description += ")";
    return out;
  } catch (const Error &) {
    return std::nullopt;
  }
}

std::string zip_content_kind(std::span<const std::byte> b) {
  bool jar = false;
  std::size_t p = 0;
  for (int n = 0; n < 64 && p + 30 <= b.size(); ++n) {
    if (le32(b.data() + p) != 0x04034b50) break;
    const std::uint16_t flags = le16(b.data() + p + 6);
    const std::uint32_t csize = le32(b.data() + p + 18);
    const std::uint16_t nlen = le16(b.data() + p + 26), xlen = le16(b.data() + p + 28);
    if (p + 30 + nlen > b.size()) break;
    const std::string_view name(reinterpret_cast<const char *>(b.data() + p + 30), nlen);
    if (name == "AndroidManifest.xml" || name == "classes.dex" || name == "resources.arsc") return "apk";
    // An iOS app archive: Payload/<name>.app/ (docs/apple-apps.md).
    if (name.starts_with("Payload/") && name.find(".app/") != std::string_view::npos) return "ipa";
    if (name == "META-INF/MANIFEST.MF" || (name.size() > 6 && name.ends_with(".class"))) jar = true;
    // A member whose size follows it (a data descriptor) ends the walk.
    if ((flags & 8) && csize == 0) break;
    p += 30ull + nlen + xlen + csize;
  }
  return jar ? "jar" : "";
}

std::optional<std::size_t> lua_chunk_length(std::span<const std::byte> b, std::size_t start, const LuaHeader &h) {
  struct Overrun {};
  std::size_t p = start + h.size;
  const int v = h.version;
  auto need = [&](std::size_t n) {
    if (p > b.size() || n > b.size() - p) throw Overrun{};
  };
  auto skip = [&](std::size_t n) {
    need(n);
    p += n;
  };
  auto byte = [&]() -> std::uint8_t {
    need(1);
    return u8(b, p++);
  };
  auto fixed = [&](int n) -> std::uint64_t {
    need(static_cast<std::size_t>(n));
    std::uint64_t x = 0;
    for (int i = 0; i < n; ++i) {
      const std::uint8_t c = u8(b, p + (h.big_endian ? i : n - 1 - i));
      x = x << 8 | c;
    }
    p += static_cast<std::size_t>(n);
    return x;
  };
  // 5.4's dumpSize: 7-bit groups, most significant first, the last byte
  // marked with 0x80.
  auto varint = [&]() -> std::uint64_t {
    std::uint64_t x = 0;
    for (int n = 0; n < 10; ++n) {
      const std::uint8_t c = byte();
      x = (x << 7) | (c & 0x7f);
      if (c & 0x80) return x;
    }
    throw Overrun{};
  };
  // A count of things: bounded by what's left, so a hostile count fails
  // fast instead of looping.
  auto count = [&](std::uint64_t n, std::size_t each) -> std::uint64_t {
    if (each != 0 && n > (b.size() - std::min(p, b.size())) / each) throw Overrun{};
    return n;
  };
  auto integer = [&]() -> std::uint64_t { return v == 0x54 ? varint() : fixed(h.int_size); };
  auto string = [&]() {
    if (v <= 0x52) {
      skip(count(fixed(h.size_t_size), 1));
    } else if (v == 0x53) {
      std::uint64_t n = byte();
      if (n == 0xff) n = fixed(h.size_t_size);
      if (n) skip(count(n - 1, 1));
    } else {
      const std::uint64_t n = varint();
      if (n) skip(count(n - 1, 1));
    }
  };
  int depth = 0;
  std::uint64_t functions = 0;
  std::function<void()> function = [&]() {
    if (++depth > 200 || ++functions > 1000000) throw Overrun{};
    if (v == 0x51) {
      string();
      integer();
      integer();
      skip(4);  // nups, numparams, is_vararg, maxstacksize
      skip(count(integer(), h.instruction_size) * h.instruction_size);
      for (std::uint64_t n = count(integer(), 1); n-- > 0;) {
        switch (byte()) {
          case 0: break;
          case 1: skip(1); break;
          case 3: skip(h.number_size); break;
          case 4: string(); break;
          default: throw Overrun{};
        }
      }
      for (std::uint64_t n = count(integer(), 1); n-- > 0;) function();
      skip(count(integer(), h.int_size) * h.int_size);  // line info
      for (std::uint64_t n = count(integer(), 1); n-- > 0;) {
        string();
        integer();
        integer();
      }
      for (std::uint64_t n = count(integer(), 1); n-- > 0;) string();
    } else if (v == 0x52) {
      integer();
      integer();
      skip(3);  // numparams, is_vararg, maxstacksize
      skip(count(integer(), h.instruction_size) * h.instruction_size);
      for (std::uint64_t n = count(integer(), 1); n-- > 0;) {
        switch (byte()) {
          case 0: break;
          case 1: skip(1); break;
          case 3: skip(h.number_size); break;
          case 4: string(); break;
          default: throw Overrun{};
        }
      }
      for (std::uint64_t n = count(integer(), 1); n-- > 0;) function();
      skip(count(integer(), 2) * 2);  // upvalues: instack, idx
      string();                       // source
      skip(count(integer(), h.int_size) * h.int_size);
      for (std::uint64_t n = count(integer(), 1); n-- > 0;) {
        string();
        integer();
        integer();
      }
      for (std::uint64_t n = count(integer(), 1); n-- > 0;) string();
    } else {
      string();  // source
      integer();
      integer();
      skip(3);
      skip(count(integer(), h.instruction_size) * h.instruction_size);
      for (std::uint64_t n = count(integer(), 1); n-- > 0;) {
        const std::uint8_t t = byte();
        if (v == 0x53) {
          switch (t) {
            case 0x00: break;                          // nil
            case 0x01: skip(1); break;                 // boolean
            case 0x03: skip(h.number_size); break;     // float
            case 0x13: skip(h.integer_size); break;    // integer
            case 0x04: case 0x14: string(); break;     // short, long string
            default: throw Overrun{};
          }
        } else {
          switch (t) {
            case 0x00: case 0x01: case 0x11: break;    // nil, false, true
            case 0x13: skip(h.number_size); break;     // float
            case 0x03: skip(h.integer_size); break;    // integer
            case 0x04: case 0x14: string(); break;
            default: throw Overrun{};
          }
        }
      }
      const std::size_t up = v == 0x53 ? 2 : 3;  // instack, idx (and 5.4's kind)
      skip(count(integer(), up) * up);
      for (std::uint64_t n = count(integer(), 1); n-- > 0;) function();
      if (v == 0x53) {
        skip(count(integer(), h.int_size) * h.int_size);
      } else {
        skip(count(integer(), 1));  // relative line info, a byte each
        for (std::uint64_t n = count(integer(), 2); n-- > 0;) {
          integer();
          integer();
        }
      }
      for (std::uint64_t n = count(integer(), 1); n-- > 0;) {
        string();
        integer();
        integer();
      }
      for (std::uint64_t n = count(integer(), 1); n-- > 0;) string();
    }
    --depth;
  };
  // Lua 5.5's dump (strings shared by reference, aligned vectors) isn't
  // walked: its chunks are named, not measured.
  if (!h.luajit && v > 0x54) return std::nullopt;
  try {
    if (h.luajit) {
      // Prototypes, each with its length, up to a zero length.
      for (std::uint64_t n = 0;; ++n) {
        if (n > 1000000) return std::nullopt;
        std::size_t q = p;
        auto len = uleb(b, q, 5);
        if (!len) return std::nullopt;
        p = q;
        if (*len == 0) break;
        skip(*len);
      }
      return p - start;
    }
    function();
    return p - start;
  } catch (const Overrun &) {
    return std::nullopt;
  }
}

}  // namespace revkit::container::detail
