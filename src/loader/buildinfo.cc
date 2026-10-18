// Go build info and cargo-auditable dependency lists (buildinfo.hh).
//
// The Go reader and the module-text parser are a C++ port of rea's
// src/go/GoBinaryImage.ts and src/go/GoModuleText.ts, and the Rust reader of
// src/rust/RustAuditableReader.ts and RustBinaryImage.ts
// (https://github.com/morluto/rea, MIT License, Copyright (c) 2026 morluto;
// THIRD_PARTY_NOTICES.md). Go's own debug/buildinfo (BSD-3-Clause) defines
// the format; where rea is stricter than Go, this follows Go and records
// what it couldn't take instead of refusing.

#include "revkit/loader/buildinfo.hh"

#include "revkit/loader/load.hh"

#include <zlib.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <set>

namespace revkit::loader {

namespace {

constexpr std::array<std::uint8_t, 14> kGoMagic = {0xff, ' ', 'G', 'o', ' ', 'b', 'u', 'i', 'l', 'd', 'i', 'n', 'f', ':'};
constexpr std::size_t kGoHeaderSize = 32;
constexpr std::uint64_t kGoMaxString = 1u << 20;      // one build-info string
constexpr std::uint64_t kGoMaxSearch = 256ull << 20;  // bytes searched for the header
constexpr std::size_t kSearchChunk = 1u << 20;

// --- UTF-8 ------------------------------------------------------------------

// The length of the valid UTF-8 sequence at s[i], or 0.
std::size_t utf8_len(std::string_view s, std::size_t i) {
  const auto c = static_cast<unsigned char>(s[i]);
  if (c < 0x80) return 1;
  std::size_t n = 0;
  if (c >= 0xc2 && c <= 0xdf) n = 2;
  else if (c >= 0xe0 && c <= 0xef) n = 3;
  else if (c >= 0xf0 && c <= 0xf4) n = 4;
  if (n == 0 || i + n > s.size()) return 0;
  for (std::size_t k = 1; k < n; ++k)
    if ((static_cast<unsigned char>(s[i + k]) & 0xc0) != 0x80) return 0;
  const auto c1 = static_cast<unsigned char>(s[i + 1]);
  if (c == 0xe0 && c1 < 0xa0) return 0;   // overlong
  if (c == 0xed && c1 >= 0xa0) return 0;  // surrogate
  if (c == 0xf0 && c1 < 0x90) return 0;   // overlong
  if (c == 0xf4 && c1 >= 0x90) return 0;  // past U+10FFFF
  return n;
}

// `s` with each invalid byte replaced by U+FFFD (what the API's strings
// must be).
std::string valid_utf8(std::string_view s) {
  std::string out;
  out.reserve(s.size());
  for (std::size_t i = 0; i < s.size();) {
    if (std::size_t n = utf8_len(s, i)) {
      out.append(s.substr(i, n));
      i += n;
    } else {
      out += "\xef\xbf\xbd";
      ++i;
    }
  }
  return out;
}

void put_utf8(std::string &out, std::uint32_t cp) {
  if (cp < 0x80) {
    out += char(cp);
  } else if (cp < 0x800) {
    out += char(0xc0 | (cp >> 6));
    out += char(0x80 | (cp & 0x3f));
  } else if (cp < 0x10000) {
    out += char(0xe0 | (cp >> 12));
    out += char(0x80 | ((cp >> 6) & 0x3f));
    out += char(0x80 | (cp & 0x3f));
  } else {
    out += char(0xf0 | (cp >> 18));
    out += char(0x80 | ((cp >> 12) & 0x3f));
    out += char(0x80 | ((cp >> 6) & 0x3f));
    out += char(0x80 | (cp & 0x3f));
  }
}

int hex_digit(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// --- Go -----------------------------------------------------------------------

std::uint64_t word(const std::byte *p, unsigned size, bool big) {
  std::uint64_t v = 0;
  for (unsigned i = 0; i < size; ++i) {
    const auto b = std::to_integer<std::uint64_t>(p[big ? i : size - 1 - i]);
    v = (v << 8) | b;
  }
  return v;
}

// Exactly `n` mapped bytes at `address`, or nullopt.
std::optional<std::string> read_exact(const ReadMemoryFn &read, std::uint64_t address, std::uint64_t n) {
  if (n > kGoMaxString || address + n < address) return std::nullopt;
  std::string out(static_cast<std::size_t>(n), '\0');
  if (n == 0) return out;
  auto span = std::span<std::byte>(reinterpret_cast<std::byte *>(out.data()), out.size());
  if (read(address, span) != n) return std::nullopt;
  return out;
}

// strconv.Unquote for one Go-quoted ("..." or `...`) string at the start
// of `in`: the value, and how many bytes the quoted form took.
std::optional<std::pair<std::string, std::size_t>> go_unquote_prefix(std::string_view in) {
  if (in.empty()) return std::nullopt;
  if (in[0] == '`') {
    const std::size_t end = in.find('`', 1);
    if (end == std::string_view::npos) return std::nullopt;
    std::string v;
    for (char c : in.substr(1, end - 1))
      if (c != '\r') v += c;
    return std::pair{std::move(v), end + 1};
  }
  if (in[0] != '"') return std::nullopt;
  std::string v;
  for (std::size_t i = 1; i < in.size();) {
    const char c = in[i];
    if (c == '"') return std::pair{std::move(v), i + 1};
    if (c == '\n') return std::nullopt;
    if (c != '\\') {
      v += c;
      ++i;
      continue;
    }
    if (i + 1 >= in.size()) return std::nullopt;
    const char e = in[i + 1];
    static constexpr std::string_view kSimple = "abfnrtv\\\"";
    static constexpr std::string_view kValue = "\a\b\f\n\r\t\v\\\"";
    if (const std::size_t k = kSimple.find(e); k != std::string_view::npos) {
      v += kValue[k];
      i += 2;
      continue;
    }
    const std::size_t digits = e == 'x' ? 2 : e == 'u' ? 4 : e == 'U' ? 8 : 0;
    if (digits) {
      if (i + 2 + digits > in.size()) return std::nullopt;
      std::uint32_t cp = 0;
      for (std::size_t k = 0; k < digits; ++k) {
        const int d = hex_digit(in[i + 2 + k]);
        if (d < 0) return std::nullopt;
        cp = (cp << 4) | std::uint32_t(d);
      }
      if (e == 'x') {
        v += char(cp);
      } else {
        if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return std::nullopt;
        put_utf8(v, cp);
      }
      i += 2 + digits;
      continue;
    }
    if (i + 3 >= in.size()) return std::nullopt;
    std::uint32_t b = 0;
    for (std::size_t k = 1; k <= 3; ++k) {
      const char d = in[i + k];
      if (d < '0' || d > '7') return std::nullopt;
      b = b * 8 + std::uint32_t(d - '0');
    }
    if (b > 255) return std::nullopt;
    v += char(b);
    i += 4;
  }
  return std::nullopt;
}

bool has_any(std::string_view s, std::string_view chars) { return s.find_first_of(chars) != std::string_view::npos; }

std::optional<GoBuildSetting> go_setting(std::string_view in) {
  GoBuildSetting out;
  std::string_view raw;
  if (!in.empty() && (in[0] == '"' || in[0] == '`')) {
    auto q = go_unquote_prefix(in);
    if (!q || q->second >= in.size() || in[q->second] != '=') return std::nullopt;
    out.key = std::move(q->first);
    raw = in.substr(q->second + 1);
  } else {
    const std::size_t eq = in.find('=');
    if (eq == std::string_view::npos || eq == 0) return std::nullopt;
    const std::string_view key = in.substr(0, eq);
    if (has_any(key, std::string_view("= \t\r\n\"`", 7))) return std::nullopt;
    out.key = std::string(key);
    raw = in.substr(eq + 1);
  }
  if (!raw.empty() && (raw[0] == '"' || raw[0] == '`')) {
    auto q = go_unquote_prefix(raw);
    if (!q || q->second != raw.size()) return std::nullopt;
    out.value = std::move(q->first);
  } else {
    if (has_any(raw, std::string_view(" \t\r\n\"`", 6))) return std::nullopt;
    out.value = std::string(raw);
  }
  out.key = valid_utf8(out.key);
  out.value = valid_utf8(out.value);
  return out;
}

std::vector<std::string_view> split_tabs(std::string_view s) {
  std::vector<std::string_view> out;
  for (;;) {
    const std::size_t t = s.find('\t');
    out.push_back(s.substr(0, t));
    if (t == std::string_view::npos) return out;
    s.remove_prefix(t + 1);
  }
}

std::optional<GoModule> module_line(const std::vector<std::string_view> &f) {
  if (f.size() != 2 && f.size() != 3) return std::nullopt;
  GoModule m;
  m.path = valid_utf8(f[0]);
  m.version = valid_utf8(f[1]);
  if (f.size() == 3) m.sum = valid_utf8(f[2]);
  return m;
}

// Reads one Go string the pointer format names: the address of a
// (pointer, length) header.
std::optional<std::string> pointer_string(const ReadMemoryFn &read, const PointerFn &pointer, std::uint64_t at,
                                          unsigned ptr, bool big, std::string *error) {
  auto hdr = read_exact(read, at, 2ull * ptr);
  if (!hdr) {
    *error = "Go build info: a string header outside memory";
    return std::nullopt;
  }
  const auto *b = reinterpret_cast<const std::byte *>(hdr->data());
  std::uint64_t data = word(b, ptr, big);
  const std::uint64_t len = word(b + ptr, ptr, big);
  if (len == 0) return std::string();
  if (pointer) data = pointer(at, data);
  if (len > kGoMaxString) {
    *error = "Go build info: a string longer than 1 MiB";
    return std::nullopt;
  }
  auto s = read_exact(read, data, len);
  if (!s) *error = "Go build info: a string outside memory";
  return s;
}

// A uvarint-prefixed string at `*at` (the inline format); advances *at.
std::optional<std::string> inline_string(const ReadMemoryFn &read, std::uint64_t *at, std::string *error) {
  std::array<std::byte, 10> buf{};
  const std::size_t got = read(*at, buf);
  std::uint64_t len = 0;
  std::size_t n = 0;
  for (; n < 10; ++n) {
    if (n >= got) {
      *error = "Go build info: a truncated length";
      return std::nullopt;
    }
    const auto b = std::to_integer<std::uint64_t>(buf[n]);
    if (n == 9 && b > 1) {
      *error = "Go build info: a length past 64 bits";
      return std::nullopt;
    }
    len |= (b & 0x7f) << (7 * n);
    if ((b & 0x80) == 0) break;
  }
  if (n == 10) {
    *error = "Go build info: an unterminated length";
    return std::nullopt;
  }
  if (len > kGoMaxString) {
    *error = "Go build info: a string longer than 1 MiB";
    return std::nullopt;
  }
  auto s = read_exact(read, *at + n + 1, len);
  if (!s) {
    *error = "Go build info: a truncated string";
    return std::nullopt;
  }
  *at += n + 1 + len;
  return s;
}

std::optional<GoBuildInfo> decode_go(const ReadMemoryFn &read, std::uint64_t at, const PointerFn &pointer,
                                     std::string *error) {
  auto hdr = read_exact(read, at, kGoHeaderSize);
  if (!hdr) {
    *error = "Go build info: a truncated header";
    return std::nullopt;
  }
  const auto ptr = static_cast<std::uint8_t>((*hdr)[14]);
  const auto flags = static_cast<std::uint8_t>((*hdr)[15]);
  GoBuildInfo out;
  out.address = at;
  out.pointer_size = ptr;
  std::optional<std::string> version, mod;
  if (flags & 2) {
    out.inline_strings = true;
    std::uint64_t p = at + kGoHeaderSize;
    version = inline_string(read, &p, error);
    if (!version) return std::nullopt;
    mod = inline_string(read, &p, error);
    if (!mod) return std::nullopt;
  } else {
    if (ptr != 4 && ptr != 8) {
      *error = "Go build info: a pointer size of " + std::to_string(ptr);
      return std::nullopt;
    }
    // The header's flag is the data's byte order (Go: data[15] != 0).
    const bool big = flags != 0;
    const auto *b = reinterpret_cast<const std::byte *>(hdr->data());
    std::uint64_t vp = word(b + 16, ptr, big), mp = word(b + 16 + ptr, ptr, big);
    if (pointer) vp = pointer(at + 16, vp);
    version = pointer_string(read, pointer, vp, ptr, big, error);
    if (!version) return std::nullopt;
    if (mp != 0) {
      if (pointer) mp = pointer(at + 16 + ptr, mp);
      mod = pointer_string(read, pointer, mp, ptr, big, error);
      if (!mod) return std::nullopt;
    } else {
      mod = std::string();
    }
  }
  if (version->empty()) {
    *error = "Go build info: no Go version";
    return std::nullopt;
  }
  out.go_version = valid_utf8(*version);
  // Go's framing: 16 sentinel bytes either side, the text ending in '\n'.
  if (mod->size() >= 33 && (*mod)[mod->size() - 17] == '\n') {
    const std::string_view text = std::string_view(*mod).substr(16, mod->size() - 32);
    out.module_text = valid_utf8(text);
    parse_go_module_text(text, out);
  } else if (!mod->empty()) {
    out.unparsed.push_back("(module text without Go's sentinels, " + std::to_string(mod->size()) + " bytes)");
  }
  return out;
}

}  // namespace

const std::string *GoBuildInfo::setting(std::string_view key) const {
  for (const GoBuildSetting &s : settings)
    if (s.key == key) return &s.value;
  return nullptr;
}

void parse_go_module_text(std::string_view text, GoBuildInfo &out) {
  bool have_path = false;
  bool have_main = out.main.has_value();
  GoModule *last = nullptr;
  // Deps are appended, so `last` is an index in that case.
  std::optional<std::size_t> last_dep;
  auto last_module = [&]() -> GoModule * {
    if (last_dep) return &out.deps[*last_dep];
    return last;
  };
  while (!text.empty()) {
    const std::size_t nl = text.find('\n');
    const bool terminated = nl != std::string_view::npos;
    const std::string_view line = text.substr(0, nl);
    text.remove_prefix(terminated ? nl + 1 : text.size());
    if (line.empty()) continue;
    auto unparsed = [&] { out.unparsed.push_back(valid_utf8(line)); };
    if (!terminated) {
      unparsed();
      continue;
    }
    if (line.starts_with("path\t") && !have_path) {
      out.path = valid_utf8(line.substr(5));
      have_path = true;
      continue;
    }
    const bool is_mod = line.starts_with("mod\t"), is_dep = line.starts_with("dep\t");
    if (is_mod || is_dep) {
      last = nullptr;
      last_dep.reset();
      auto m = module_line(split_tabs(line.substr(4)));
      if (m && (is_dep || !have_main)) {
        if (is_mod) {
          out.main = std::move(*m);
          have_main = true;
          last = &*out.main;
        } else {
          out.deps.push_back(std::move(*m));
          last_dep = out.deps.size() - 1;
        }
        continue;
      }
    } else if (line.starts_with("=>\t")) {
      const auto f = split_tabs(line.substr(3));
      GoModule *target = last_module();
      last = nullptr;
      last_dep.reset();
      if (f.size() == 3 && target) {
        target->replacement = GoModuleReplacement{valid_utf8(f[0]), valid_utf8(f[1]), valid_utf8(f[2])};
        continue;
      }
    } else if (line.starts_with("build\t")) {
      if (auto s = go_setting(line.substr(6))) {
        out.settings.push_back(std::move(*s));
        continue;
      }
    }
    unparsed();
  }
}

std::optional<GoBuildInfo> find_go_buildinfo(const ReadMemoryFn &read, std::uint64_t start, std::uint64_t size,
                                             const PointerFn &pointer, std::string *error) {
  std::string scratch;
  if (!error) error = &scratch;
  error->clear();
  if (size == 0) return std::nullopt;
  std::uint64_t end = start + size < start ? ~0ull : start + size;
  if (end - start > kGoMaxSearch) end = start + kGoMaxSearch;
  std::uint64_t at = (start + 15) & ~15ull;
  if (at < start) return std::nullopt;
  std::vector<std::byte> buf;
  while (at < end && end - at >= kGoMagic.size()) {
    const std::uint64_t n = std::min<std::uint64_t>(kSearchChunk, end - at);
    buf.assign(static_cast<std::size_t>(n), std::byte{0});
    read(at, buf);
    // Chunks start 16-aligned and the magic is shorter than 16 bytes, so
    // no aligned candidate straddles two chunks.
    for (std::size_t off = 0; off + kGoMagic.size() <= buf.size(); off += 16) {
      if (std::memcmp(buf.data() + off, kGoMagic.data(), kGoMagic.size()) != 0) continue;
            return decode_go(read, at + off, pointer, error);
    }
    at += n;
  }
  return std::nullopt;
}

std::optional<GoBuildInfo> read_go_buildinfo(const Image &image, std::string *error) {
  std::string scratch;
  if (!error) error = &scratch;
  error->clear();
  std::optional<std::pair<std::uint64_t, std::uint64_t>> region;
  for (const Section &s : image.sections) {
    const std::string_view n = s.name;
    if ((n == ".go.buildinfo" || n == "__go_buildinfo" || n.ends_with(",__go_buildinfo")) && s.alloc && s.file_size) {
      region = {s.addr, std::min(s.size, s.file_size)};
      break;
    }
  }
  if (!region && image.format == Format::elf) {
    constexpr std::uint32_t kPtLoad = 1, kPfX = 1, kPfW = 2;
    for (const Segment &s : image.segments)
      if (s.type == kPtLoad && (s.flags & (kPfX | kPfW)) == kPfW && s.mem_size) {
        // Only the bytes from the file: the zero fill after them holds no header.
        region = {s.vaddr, std::min(s.mem_size, s.file_size)};
        break;
      }
  } else if (!region && image.format == Format::pe) {
    // IMAGE_SCN_CNT_INITIALIZED_DATA | MEM_READ | MEM_WRITE, any alignment
    // bits (Go's peExe.DataStart).
    for (const Section &s : image.sections)
      if (s.addr != 0 && s.file_size != 0 && (s.flags & ~std::uint64_t(0x00600000)) == 0xc0000040) {
        region = {s.addr, std::min(s.virtual_size ? s.virtual_size : s.size, s.file_size)};
        break;
      }
  } else if (!region && image.format != Format::raw) {
    // Other formats (Mach-O): the first writable, non-executable data.
    for (const Section &s : image.sections)
      if (s.alloc && s.perms.write && !s.perms.exec && s.file_size) {
        region = {s.addr, std::min(s.size, s.file_size)};
        break;
      }
  }
  if (!region) return std::nullopt;
  const Memory &mem = image.memory;
  // Search only bytes the file has (a header can't be in zero fill, and a
  // hostile size can't make the search read 256 MiB of nothing): the
  // file-backed part of the regions from the start on, while contiguous.
  {
    std::uint64_t at = region->first, backed = 0;
    while (backed < region->second) {
      const Region *r = mem.find(at);
      if (!r || at - r->start >= r->file_size) break;
      const std::uint64_t n = std::min(r->file_size - (at - r->start), region->second - backed);
      backed += n;
      at += n;
      if (at - r->start < r->file_size) break;  // ended inside this region
    }
    region->second = backed;
  }
  ReadMemoryFn read = [&mem](std::uint64_t a, std::span<std::byte> out) { return mem.read(a, out); };
  // A pointer the file stores is a link-time address: a RELATIVE
  // relocation there says where it goes; otherwise it moves with the image.
  const std::uint64_t delta = image.image_base - image.file_base;
  PointerFn pointer = [&image, delta](std::uint64_t at, std::uint64_t raw) {
    const auto &rel = image.relocations;
    auto it = std::lower_bound(rel.begin(), rel.end(), at, [](const Relocation &r, std::uint64_t a) { return r.address < a; });
    if (it != rel.end() && it->address == at && it->target) return *it->target;
    return raw + delta;
  };
  return find_go_buildinfo(read, region->first, region->second, pointer, error);
}

// --- Rust (cargo-auditable) -------------------------------------------------------

namespace {

// A bounded JSON reader for cargo-auditable's document: the object's
// "format" and "packages"; anything else is skipped.
class AuditJson {
 public:
  explicit AuditJson(std::string_view s) : s_(s) {}

  std::optional<RustAuditInfo> document(std::string *error) {
    RustAuditInfo out;
    ws();
    if (!object([&](const std::string &key) {
          if (key == "format") return uint_value(&out.format);
          if (key == "packages") return array([&] { return package(out); });
          return skip(1);
        })) {
      *error = err_.empty() ? "invalid JSON" : err_;
      return std::nullopt;
    }
    ws();
    if (i_ != s_.size()) {
      *error = "text after the JSON document";
      return std::nullopt;
    }
    return out;
  }

 private:
  static constexpr int kMaxDepth = 32;

  bool fail(std::string m) {
    if (err_.empty()) err_ = std::move(m) + " at byte " + std::to_string(i_);
    return false;
  }
  void ws() {
    while (i_ < s_.size() && (s_[i_] == ' ' || s_[i_] == '\t' || s_[i_] == '\n' || s_[i_] == '\r')) ++i_;
  }
  bool eat(char c) {
    ws();
    if (i_ < s_.size() && s_[i_] == c) {
      ++i_;
      return true;
    }
    return false;
  }
  template <class F>
  bool object(F &&member, int depth = 1) {
    if (depth > kMaxDepth) return fail("JSON nested deeper than 32");
    if (!eat('{')) return fail("expected an object");
    if (eat('}')) return true;
    for (;;) {
      ws();
      std::string key;
      if (!string(&key)) return false;
      if (!eat(':')) return fail("expected ':'");
      ws();
      if (!member(key)) return false;
      if (eat(',')) continue;
      if (eat('}')) return true;
      return fail("expected ',' or '}'");
    }
  }
  template <class F>
  bool array(F &&element, int depth = 2) {
    if (depth > kMaxDepth) return fail("JSON nested deeper than 32");
    if (!eat('[')) return fail("expected an array");
    if (eat(']')) return true;
    for (;;) {
      ws();
      if (!element()) return false;
      if (eat(',')) continue;
      if (eat(']')) return true;
      return fail("expected ',' or ']'");
    }
  }
  bool string(std::string *out) {
    if (i_ >= s_.size() || s_[i_] != '"') return fail("expected a string");
    ++i_;
    std::string raw;
    while (i_ < s_.size()) {
      const char c = s_[i_];
      if (c == '"') {
        ++i_;
        *out = valid_utf8(raw);
        return true;
      }
      if (static_cast<unsigned char>(c) < 0x20) return fail("a control character in a string");
      if (c != '\\') {
        raw += c;
        ++i_;
        continue;
      }
      if (i_ + 1 >= s_.size()) break;
      const char e = s_[i_ + 1];
      i_ += 2;
      switch (e) {
        case '"': raw += '"'; break;
        case '\\': raw += '\\'; break;
        case '/': raw += '/'; break;
        case 'b': raw += '\b'; break;
        case 'f': raw += '\f'; break;
        case 'n': raw += '\n'; break;
        case 'r': raw += '\r'; break;
        case 't': raw += '\t'; break;
        case 'u': {
          std::uint32_t cp = 0;
          if (!hex4(&cp)) return false;
          if (cp >= 0xd800 && cp < 0xdc00 && i_ + 1 < s_.size() && s_[i_] == '\\' && s_[i_ + 1] == 'u') {
            const std::size_t save = i_;
            i_ += 2;
            std::uint32_t lo = 0;
            if (hex4(&lo) && lo >= 0xdc00 && lo < 0xe000) {
              cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
            } else {
              i_ = save;
              cp = 0xfffd;
            }
          } else if (cp >= 0xd800 && cp < 0xe000) {
            cp = 0xfffd;
          }
          put_utf8(raw, cp);
          break;
        }
        default: return fail("a bad escape in a string");
      }
    }
    return fail("an unterminated string");
  }
  bool hex4(std::uint32_t *cp) {
    if (i_ + 4 > s_.size()) return fail("a short \\u escape");
    for (int k = 0; k < 4; ++k) {
      const int d = hex_digit(s_[i_ + k]);
      if (d < 0) return fail("a bad \\u escape");
      *cp = (*cp << 4) | std::uint32_t(d);
    }
    i_ += 4;
    return true;
  }
  // A non-negative integer that fits 32 bits.
  bool uint_value(std::uint32_t *out) {
    ws();
    std::uint64_t v = 0;
    const std::size_t start = i_;
    while (i_ < s_.size() && s_[i_] >= '0' && s_[i_] <= '9') {
      v = v * 10 + std::uint64_t(s_[i_] - '0');
      if (v > 0xffffffffull) return fail("an integer past 32 bits");
      ++i_;
    }
    if (i_ == start) return fail("expected a non-negative integer");
    if (i_ < s_.size() && (s_[i_] == '.' || s_[i_] == 'e' || s_[i_] == 'E')) return fail("expected an integer");
    *out = static_cast<std::uint32_t>(v);
    return true;
  }
  bool literal(std::string_view word) {
    if (s_.substr(i_, word.size()) != word) return fail("an unknown literal");
    i_ += word.size();
    return true;
  }
  bool boolean(bool *out) {
    ws();
    if (s_.substr(i_, 4) == "true") {
      *out = true;
      i_ += 4;
      return true;
    }
    if (s_.substr(i_, 5) == "false") {
      *out = false;
      i_ += 5;
      return true;
    }
    return fail("expected true or false");
  }
  // Skips one value of any kind.
  bool skip(int depth) {
    ws();
    if (i_ >= s_.size()) return fail("a truncated value");
    const char c = s_[i_];
    if (c == '{') return object([&](const std::string &) { return skip(depth + 1); }, depth + 1);
    if (c == '[') return array([&] { return skip(depth + 1); }, depth + 1);
    if (c == '"') {
      std::string ignored;
      return string(&ignored);
    }
    if (c == 't') return literal("true");
    if (c == 'f') return literal("false");
    if (c == 'n') return literal("null");
    const std::size_t start = i_;
    if (c == '-') ++i_;
    while (i_ < s_.size() && ((s_[i_] >= '0' && s_[i_] <= '9') || s_[i_] == '.' || s_[i_] == 'e' ||
                              s_[i_] == 'E' || s_[i_] == '+' || s_[i_] == '-'))
      ++i_;
    if (i_ == start || (c == '-' && i_ == start + 1)) return fail("an unexpected character");
    return true;
  }
  bool package(RustAuditInfo &out) {
    RustPackage p;
    bool name = false, version = false, source = false;
    const std::size_t index = out.packages.size();
    if (!object(
            [&](const std::string &key) {
              if (key == "name") {
                name = true;
                return string_member(&p.name);
              }
              if (key == "version") {
                version = true;
                return string_member(&p.version);
              }
              if (key == "source") {
                source = true;
                return string_member(&p.source);
              }
              if (key == "kind") {
                if (!string_member(&p.kind)) return false;
                if (p.kind != "runtime" && p.kind != "build") return fail("package kind \"" + p.kind + "\"");
                return true;
              }
              if (key == "root") return boolean(&p.root);
              if (key == "dependencies")
                return array(
                    [&] {
                      std::uint32_t d = 0;
                      if (!uint_value(&d)) return false;
                      p.dependencies.push_back(d);
                      return true;
                    },
                    3);
              return skip(3);
            },
            2))
      return false;
    if (!name || !version || !source || p.name.empty() || p.version.empty() || p.source.empty())
      return fail("package " + std::to_string(index) + " has no name, version or source");
    out.packages.push_back(std::move(p));
    return true;
  }
  bool string_member(std::string *out) {
    ws();
    return string(out);
  }

  std::string_view s_;
  std::size_t i_ = 0;
  std::string err_;
};

// Inflates a zlib stream of at most `limit` bytes; trailing zero bytes
// (section padding) are allowed, anything else after the stream is not.
std::optional<std::string> inflate_bounded(std::span<const std::byte> in, std::size_t limit, std::string *error) {
  z_stream z{};
  if (inflateInit(&z) != Z_OK) {
    *error = "zlib failed to start";
    return std::nullopt;
  }
  std::string out;
  z.next_in = reinterpret_cast<Bytef *>(const_cast<std::byte *>(in.data()));
  z.avail_in = static_cast<uInt>(in.size());
  std::array<char, 64 * 1024> buf;
  int rc = Z_OK;
  while (rc == Z_OK) {
    z.next_out = reinterpret_cast<Bytef *>(buf.data());
    z.avail_out = static_cast<uInt>(buf.size());
    rc = inflate(&z, Z_NO_FLUSH);
    if (rc != Z_OK && rc != Z_STREAM_END) break;
    const std::size_t got = buf.size() - z.avail_out;
    if (out.size() + got > limit) {
      inflateEnd(&z);
      *error = "the inflated dependency list is larger than " + std::to_string(limit) + " bytes";
      return std::nullopt;
    }
    out.append(buf.data(), got);
    if (rc == Z_OK && got == 0 && z.avail_in == 0) {
      rc = Z_BUF_ERROR;
      break;
    }
  }
  const std::size_t rest = z.avail_in;
  inflateEnd(&z);
  if (rc != Z_STREAM_END) {
    *error = "the dependency section is not a complete zlib stream";
    return std::nullopt;
  }
  for (std::size_t k = in.size() - rest; k < in.size(); ++k)
    if (in[k] != std::byte{0}) {
      *error = "bytes after the dependency section's zlib stream";
      return std::nullopt;
    }
  return out;
}

bool is_dep_section(std::string_view n) { return n == ".dep-v0" || n.ends_with(",.dep-v0"); }

}  // namespace

std::optional<RustAuditInfo> parse_rust_audit(std::span<const std::byte> section, std::string *error) {
  std::string scratch;
  if (!error) error = &scratch;
  error->clear();
  if (section.empty()) {
    *error = "the dependency section is empty";
    return std::nullopt;
  }
  if (section.size() > kRustAuditMaxCompressed) {
    *error = "the dependency section is larger than 1 MiB";
    return std::nullopt;
  }
  const std::size_t limit = std::min<std::size_t>(kRustAuditMaxInflated, section.size() * 64);
  auto json = inflate_bounded(section, limit, error);
  if (!json) return std::nullopt;
  AuditJson reader(*json);
  auto out = reader.document(error);
  if (!out) {
    *error = "cargo-auditable JSON: " + *error;
    return std::nullopt;
  }
  for (std::size_t i = 0; i < out->packages.size(); ++i) {
    const RustPackage &p = out->packages[i];
    for (std::uint32_t d : p.dependencies)
      if (d >= out->packages.size()) {
        *error = "cargo-auditable JSON: package " + std::to_string(i) + " depends on " + std::to_string(d) +
                 ", outside the list";
        return std::nullopt;
      }
    if (p.root) {
      if (out->root) {
        *error = "cargo-auditable JSON: more than one root package";
        return std::nullopt;
      }
      out->root = static_cast<std::uint32_t>(i);
    }
  }
  out->compressed_size = section.size();
  out->uncompressed_size = json->size();
  return out;
}

std::optional<RustAuditInfo> read_rust_audit(const Image &image, std::string *error) {
  std::string scratch;
  if (!error) error = &scratch;
  error->clear();
  const Section *found = nullptr;
  for (const Section &s : image.sections) {
    if (!is_dep_section(s.name)) continue;
    if (found) {
      *error = "two cargo-auditable .dep-v0 sections";
      return std::nullopt;
    }
    found = &s;
  }
  if (!found) return std::nullopt;
  std::span<const std::byte> bytes = section_bytes(image, *found);
  if (bytes.empty()) {
    *error = "the .dep-v0 section has no bytes in the file";
    return std::nullopt;
  }
  return parse_rust_audit(bytes, error);
}

BuildMetadata read_build_metadata(const Image &image) {
  BuildMetadata out;
  std::string error;
  out.go = read_go_buildinfo(image, &error);
  if (!error.empty()) out.warnings.push_back(error);
  out.rust = read_rust_audit(image, &error);
  if (!error.empty()) out.warnings.push_back(error);
  if (const Section *c = find_section(image, ".comment"); c && !c->alloc) {
    std::span<const std::byte> b = section_bytes(image, *c);
    std::string_view text(reinterpret_cast<const char *>(b.data()), std::min<std::size_t>(b.size(), 64 * 1024));
    for (std::size_t at = 0; at < text.size();) {
      std::size_t nul = text.find('\0', at);
      if (nul == std::string_view::npos) nul = text.size();
      const std::string_view s = text.substr(at, nul - at);
      if (s.starts_with("rustc version ") && s.size() < 256) {
        out.rustc_version = valid_utf8(s);
        break;
      }
      at = nul + 1;
    }
  }
  // "/rustc/<40 hex>/" in read-only data, each range once.
  std::vector<std::pair<std::uint64_t, std::uint64_t>> ranges;  // file offsets
  for (const Section &s : image.sections) {
    if (!s.alloc || s.perms.write || s.file_size == 0) continue;
    std::span<const std::byte> b = section_bytes(image, s);
    if (b.empty()) continue;
    const auto off = static_cast<std::uint64_t>(b.data() - image.file->data());
    ranges.emplace_back(off, off + b.size());
  }
  std::sort(ranges.begin(), ranges.end());
  std::vector<std::pair<std::uint64_t, std::uint64_t>> merged;
  for (const auto &r : ranges) {
    if (!merged.empty() && r.first <= merged.back().second)
      merged.back().second = std::max(merged.back().second, r.second);
    else
      merged.push_back(r);
  }
  std::set<std::string> seen;
  std::uint64_t budget = kGoMaxSearch;
  constexpr std::string_view kPrefix = "/rustc/";
  for (const auto &[from, to] : merged) {
    if (out.rustc_commits.size() >= 16 || budget == 0) break;
    const std::uint64_t len = std::min(to - from, budget);
    budget -= len;
    const std::string_view text(reinterpret_cast<const char *>(image.file->data() + from), len);
    for (std::size_t at = text.find(kPrefix); at != std::string_view::npos; at = text.find(kPrefix, at + 1)) {
      const std::size_t h = at + kPrefix.size();
      if (h + 41 > text.size() || text[h + 40] != '/') continue;
      const std::string_view hash = text.substr(h, 40);
      if (!std::all_of(hash.begin(), hash.end(), [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }))
        continue;
      if (seen.insert(std::string(hash)).second) {
        out.rustc_commits.emplace_back(hash);
        if (out.rustc_commits.size() >= 16) break;
      }
    }
  }
  return out;
}

}  // namespace revkit::loader
