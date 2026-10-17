#include "data_settings.h"

#include <array>
#include <cctype>
#include <cstdio>

namespace revkit::backend {
namespace {

using F = DataSettings::Format;
using S = DataSettings::Sign;
using E = DataSettings::Endian;
using P = DataSettings::Padding;
using T = DataSettings::Termination;
using K = DataSettings::Pointer;

constexpr std::array<std::string_view, 6> kFormats = {"", "hex", "decimal", "octal", "binary", "char"};
constexpr std::array<std::string_view, 3> kSigns = {"", "signed", "unsigned"};
constexpr std::array<std::string_view, 3> kEndians = {"", "little", "big"};
constexpr std::array<std::string_view, 3> kPads = {"", "padded", "unpadded"};
constexpr std::array<std::string_view, 3> kTerms = {"", "nul", "all"};
constexpr std::array<std::string_view, 4> kPointers = {"", "absolute", "image-base", "relative"};

template <class Enum, std::size_t N>
bool Named(const std::array<std::string_view, N> &names, std::string_view v, Enum &out) {
  for (std::size_t i = 1; i < N; ++i)
    if (names[i] == v) {
      out = static_cast<Enum>(i);
      return true;
    }
  return false;
}

std::optional<std::uint64_t> ParseHex(std::string_view s) {
  if (s.empty() || s.size() > 16) return std::nullopt;
  std::uint64_t v = 0;
  for (char c : s) {
    const int d = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
    if (d < 0) return std::nullopt;
    v = v << 4 | static_cast<std::uint64_t>(d);
  }
  return v;
}

std::optional<std::int32_t> ParseInt(std::string_view s) {
  bool neg = false;
  if (!s.empty() && s[0] == '-') neg = true, s.remove_prefix(1);
  if (s.empty() || s.size() > 3) return std::nullopt;
  int v = 0;
  for (char c : s) {
    if (c < '0' || c > '9') return std::nullopt;
    v = v * 10 + (c - '0');
  }
  return neg ? -v : v;
}

void Utf8(std::string &out, std::uint32_t cp) {
  if (cp < 0x80) {
    out += static_cast<char>(cp);
  } else if (cp < 0x800) {
    out += static_cast<char>(0xc0 | (cp >> 6));
    out += static_cast<char>(0x80 | (cp & 0x3f));
  } else if (cp < 0x10000) {
    out += static_cast<char>(0xe0 | (cp >> 12));
    out += static_cast<char>(0x80 | ((cp >> 6) & 0x3f));
    out += static_cast<char>(0x80 | (cp & 0x3f));
  } else {
    out += static_cast<char>(0xf0 | (cp >> 18));
    out += static_cast<char>(0x80 | ((cp >> 12) & 0x3f));
    out += static_cast<char>(0x80 | ((cp >> 6) & 0x3f));
    out += static_cast<char>(0x80 | (cp & 0x3f));
  }
}

void Escape(std::string &out, const char *fmt, std::uint32_t v) {
  char buf[16];
  std::snprintf(buf, sizeof buf, fmt, v);
  out += buf;
}

// One code point into a quoted string.
void Put(std::string &out, std::uint32_t cp) {
  switch (cp) {
    case 0: out += "\\0"; return;
    case '\n': out += "\\n"; return;
    case '\t': out += "\\t"; return;
    case '\r': out += "\\r"; return;
    case '"': out += "\\\""; return;
    case '\\': out += "\\\\"; return;
    default: break;
  }
  if (cp < 0x20 || cp == 0x7f) return Escape(out, "\\x%02x", cp);
  if (cp >= 0x80 && cp < 0xa0) return Escape(out, "\\u%04x", cp);
  if ((cp >= 0xd800 && cp < 0xe000) || cp > 0x10ffff) return Escape(out, cp > 0xffff ? "\\U%08x" : "\\u%04x", cp);
  Utf8(out, cp);
}

// windows-1252's 0x80..0x9f (0: unassigned, shown as the byte).
constexpr std::array<std::uint16_t, 32> kCp1252 = {
    0x20ac, 0,      0x201a, 0x0192, 0x201e, 0x2026, 0x2020, 0x2021, 0x02c6, 0x2030, 0x0160,
    0x2039, 0x0152, 0,      0x017d, 0,      0,      0x2018, 0x2019, 0x201c, 0x201d, 0x2022,
    0x2013, 0x2014, 0x02dc, 0x2122, 0x0161, 0x203a, 0x0153, 0,      0x017e, 0x0178};

}  // namespace

bool IsDataSettingsTag(std::string_view tag) {
  return tag == kDataSettingsTag || tag.starts_with(kDataFieldSettingsPrefix) || tag.starts_with(kDataTypeSettingsPrefix);
}

std::string DataSettingsTag(std::string_view field) {
  return field.empty() ? std::string(kDataSettingsTag) : std::string(kDataFieldSettingsPrefix) + std::string(field);
}

std::string DataTypeSettingsTag(std::string_view type) { return std::string(kDataTypeSettingsPrefix) + std::string(type); }

DataSettings DataSettings::over(const DataSettings &u) const {
  DataSettings o = *this;
  if (o.format == F::unset) o.format = u.format;
  if (o.sign == S::unset) o.sign = u.sign;
  if (o.endian == E::unset) o.endian = u.endian;
  if (o.padding == P::unset) o.padding = u.padding;
  if (o.charset.empty()) o.charset = u.charset;
  if (o.termination == T::unset) o.termination = u.termination;
  if (o.pointer == K::unset) o.pointer = u.pointer;
  if (!o.mask) o.mask = u.mask;
  if (!o.shift) o.shift = u.shift;
  return o;
}

std::string DataSettings::encode() const {
  std::string out;
  auto put = [&](std::string_view k, std::string_view v) {
    if (v.empty()) return;
    if (!out.empty()) out += ';';
    out += k;
    out += '=';
    out += v;
  };
  put("format", kFormats[static_cast<std::size_t>(format)]);
  put("sign", kSigns[static_cast<std::size_t>(sign)]);
  put("endian", kEndians[static_cast<std::size_t>(endian)]);
  put("pad", kPads[static_cast<std::size_t>(padding)]);
  put("charset", charset);
  put("term", kTerms[static_cast<std::size_t>(termination)]);
  put("pointer", kPointers[static_cast<std::size_t>(pointer)]);
  if (mask) {
    char buf[24];
    std::snprintf(buf, sizeof buf, "%llx", static_cast<unsigned long long>(*mask));
    put("mask", buf);
  }
  if (shift) put("shift", std::to_string(*shift));
  return out;
}

std::optional<DataSettings> DataSettings::parse(std::string_view text) {
  DataSettings s;
  while (!text.empty()) {
    const std::size_t semi = text.find(';');
    std::string_view item = text.substr(0, semi);
    text = semi == std::string_view::npos ? std::string_view() : text.substr(semi + 1);
    const std::size_t eq = item.find('=');
    if (eq == std::string_view::npos) return std::nullopt;
    const std::string_view k = item.substr(0, eq), v = item.substr(eq + 1);
    bool ok = true;
    if (k == "format") ok = Named(kFormats, v, s.format);
    else if (k == "sign") ok = Named(kSigns, v, s.sign);
    else if (k == "endian") ok = Named(kEndians, v, s.endian);
    else if (k == "pad") ok = Named(kPads, v, s.padding);
    else if (k == "charset") {
      auto c = CanonicalCharset(v);
      ok = c.has_value();
      if (c) s.charset = *c;
    } else if (k == "term") ok = Named(kTerms, v, s.termination);
    else if (k == "pointer") ok = Named(kPointers, v, s.pointer);
    else if (k == "mask") {
      s.mask = ParseHex(v);
      ok = s.mask && *s.mask != 0;
    } else if (k == "shift") {
      s.shift = ParseInt(v);
      ok = s.shift && *s.shift >= -63 && *s.shift <= 63;
    }
    // (an unknown key: a later daemon's setting, skipped)
    if (!ok) return std::nullopt;
  }
  return s;
}

std::optional<DataSettings> DataSettings::from_proto(const pb::DataSettings &p, std::string *err) {
  DataSettings s;
  auto range = [&](int v, int max, const char *what) {
    if (v >= 0 && v <= max) return true;
    *err = std::string("settings.") + what + " is out of range";
    return false;
  };
  if (!range(p.format(), 5, "format") || !range(p.signedness(), 2, "signedness") || !range(p.endian(), 2, "endian") ||
      !range(p.padding(), 2, "padding") || !range(p.termination(), 2, "termination") ||
      !range(p.pointer_kind(), 3, "pointer_kind"))
    return std::nullopt;
  s.format = static_cast<F>(p.format());
  s.sign = static_cast<S>(p.signedness());
  s.endian = static_cast<E>(p.endian());
  s.padding = static_cast<P>(p.padding());
  s.termination = static_cast<T>(p.termination());
  s.pointer = static_cast<K>(p.pointer_kind());
  if (!p.charset().empty()) {
    auto c = CanonicalCharset(p.charset());
    if (!c) {
      std::string names;
      for (std::string_view n : DataCharsets()) names += (names.empty() ? "" : ", ") + std::string(n);
      *err = "settings.charset \"" + p.charset().substr(0, 64) + "\" is not one of " + names;
      return std::nullopt;
    }
    s.charset = *c;
  }
  if (p.has_pointer_mask()) {
    if (p.pointer_mask() == 0) {
      *err = "settings.pointer_mask must keep some bit";
      return std::nullopt;
    }
    s.mask = p.pointer_mask();
  }
  if (p.has_pointer_shift()) {
    if (p.pointer_shift() < -63 || p.pointer_shift() > 63) {
      *err = "settings.pointer_shift must be from -63 to 63";
      return std::nullopt;
    }
    s.shift = p.pointer_shift();
  }
  return s;
}

pb::DataSettings DataSettings::to_proto() const {
  pb::DataSettings p;
  p.set_format(static_cast<pb::DataFormat>(format));
  p.set_signedness(static_cast<pb::DataSignedness>(sign));
  p.set_endian(static_cast<pb::DataEndian>(endian));
  p.set_padding(static_cast<pb::DataPadding>(padding));
  p.set_charset(charset);
  p.set_termination(static_cast<pb::StringTermination>(termination));
  p.set_pointer_kind(static_cast<pb::PointerKind>(pointer));
  if (mask) p.set_pointer_mask(*mask);
  if (shift) p.set_pointer_shift(*shift);
  return p;
}

const std::vector<std::string_view> &DataCharsets() {
  static const std::vector<std::string_view> kAll = {"US-ASCII", "ISO-8859-1", "windows-1252", "UTF-8",    "UTF-16",
                                                     "UTF-16LE", "UTF-16BE",   "UTF-32",       "UTF-32LE", "UTF-32BE"};
  return kAll;
}

std::optional<std::string> CanonicalCharset(std::string_view name) {
  std::string k;
  for (char c : name)
    if (c != '-' && c != '_' && c != ' ') k += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  static const std::map<std::string_view, std::string_view> kAliases = {
      {"usascii", "US-ASCII"},    {"ascii", "US-ASCII"},         {"iso88591", "ISO-8859-1"}, {"latin1", "ISO-8859-1"},
      {"windows1252", "windows-1252"}, {"cp1252", "windows-1252"}, {"utf8", "UTF-8"},         {"utf16", "UTF-16"},
      {"utf16le", "UTF-16LE"},    {"utf16be", "UTF-16BE"},       {"utf32", "UTF-32"},       {"utf32le", "UTF-32LE"},
      {"utf32be", "UTF-32BE"}};
  auto it = kAliases.find(k);
  if (it == kAliases.end()) return std::nullopt;
  return std::string(it->second);
}

DataSettings DataSettingsMap::at(std::uint64_t item, std::string_view field, std::string_view type) const {
  DataSettings own;
  if (auto it = items.find({item, std::string(field)}); it != items.end()) own = it->second;
  if (auto it = types.find(type); it != types.end()) return own.over(it->second);
  return own;
}

std::string FormatInteger(std::string_view bytes, bool big_endian, bool is_signed, DataSettings::Format format,
                          DataSettings::Padding padding) {
  const std::size_t n = bytes.size();
  if (n == 0 || n > 8) return "??";
  std::uint64_t v = 0;
  for (std::size_t i = 0; i < n; ++i)
    v |= std::uint64_t{static_cast<unsigned char>(bytes[big_endian ? n - 1 - i : i])} << (8 * i);
  const unsigned bits = static_cast<unsigned>(8 * n);
  const std::int64_t sv = bits == 64 ? static_cast<std::int64_t>(v) : static_cast<std::int64_t>(v << (64 - bits)) >> (64 - bits);
  const bool negative = is_signed && sv < 0;
  const std::uint64_t mag = negative ? static_cast<std::uint64_t>(-static_cast<__int128>(sv)) : v;
  auto digits = [&](unsigned base, unsigned width, std::string_view suffix) {
    std::string d;
    std::uint64_t x = mag;
    do {
      d.insert(d.begin(), "0123456789abcdef"[x % base]);
      x /= base;
    } while (x);
    if (d.size() < width) d.insert(0, width - d.size(), '0');
    return (negative ? "-" : "") + d + std::string(suffix);
  };
  switch (format) {
    case F::decimal: return digits(10, 0, "");
    case F::octal: return digits(8, padding == P::padded ? (bits + 2) / 3 : 0, "o");
    case F::binary: return digits(2, padding == P::padded ? bits : 0, "b");
    case F::character: {
      std::string out = "'";
      for (std::size_t i = 0; i < n; ++i) {
        const auto c = static_cast<unsigned>((v >> (8 * (n - 1 - i))) & 0xff);
        if (c == '\'' || c == '\\') out += '\\', out += static_cast<char>(c);
        else if (c >= 0x20 && c < 0x7f) out += static_cast<char>(c);
        else Escape(out, "\\x%02x", c);
      }
      return out + "'";
    }
    case F::hex:
    case F::unset:
    default: {
      const bool padded = padding == P::padded || (padding == P::unset && !is_signed);
      return digits(16, padded ? 2 * static_cast<unsigned>(n) : 0, "h");
    }
  }
}

std::size_t Utf8Sequence(std::string_view s, std::size_t i) {
  const auto at = [&](std::size_t k) { return static_cast<std::uint32_t>(static_cast<unsigned char>(s[k])); };
  const std::uint32_t b = at(i);
  if (b < 0x80) return 1;
  const std::size_t len = b >= 0xf0 && b < 0xf5 ? 4 : b >= 0xe0 && b < 0xf0 ? 3 : b >= 0xc2 && b < 0xe0 ? 2 : 0;
  if (len == 0 || i + len > s.size()) return 0;
  std::uint32_t cp = len == 4 ? b & 0x07 : len == 3 ? b & 0x0f : b & 0x1f;
  for (std::size_t k = 1; k < len; ++k) {
    const std::uint32_t c = at(i + k);
    if ((c & 0xc0) != 0x80) return 0;
    cp = cp << 6 | (c & 0x3f);
  }
  if ((len == 3 && cp < 0x800) || (len == 4 && (cp < 0x10000 || cp > 0x10ffff)) || (cp >= 0xd800 && cp < 0xe000)) return 0;
  return len;
}

std::string_view CharsetPrefix(std::string_view charset) {
  if (charset.starts_with("UTF-16")) return "u";
  if (charset.starts_with("UTF-32")) return "U";
  return "";
}

std::string QuoteChars(std::string_view bytes, std::string_view charset, bool big_endian, bool all,
                       std::string_view prefix) {
  std::string out(prefix);
  out += '"';
  const auto byte = [&](std::size_t i) { return static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[i])); };
  if (charset.starts_with("UTF-16") || charset.starts_with("UTF-32")) {
    const std::size_t unit = charset.starts_with("UTF-16") ? 2 : 4;
    const bool big = charset.ends_with("BE") ? true : charset.ends_with("LE") ? false : big_endian;
    auto at = [&](std::size_t i) {
      std::uint32_t v = 0;
      for (std::size_t k = 0; k < unit; ++k) v |= byte(i + (big ? unit - 1 - k : k)) << (8 * k);
      return v;
    };
    for (std::size_t i = 0; i + unit <= bytes.size(); i += unit) {
      std::uint32_t cp = at(i);
      if (cp == 0 && !all) break;
      if (unit == 2 && cp >= 0xd800 && cp < 0xdc00 && i + 2 * unit <= bytes.size()) {
        const std::uint32_t lo = at(i + unit);
        if (lo >= 0xdc00 && lo < 0xe000) {
          cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
          i += unit;
        }
      }
      Put(out, cp);
    }
    return out + '"';
  }
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    const std::uint32_t b = byte(i);
    if (b == 0 && !all) break;
    if (b < 0x80) {
      Put(out, b);
    } else if (charset == "ISO-8859-1") {
      Put(out, b);
    } else if (charset == "windows-1252") {
      if (b >= 0xa0) Put(out, b);
      else if (std::uint32_t cp = kCp1252[b - 0x80]) Put(out, cp);
      else Escape(out, "\\x%02x", b);
    } else if (charset == "UTF-8") {
      // A well-formed sequence, else the byte escaped.
      const std::size_t len = Utf8Sequence(bytes, i);
      if (len == 0) {
        Escape(out, "\\x%02x", b);
        continue;
      }
      std::uint32_t cp = len == 4 ? b & 0x07 : len == 3 ? b & 0x0f : b & 0x1f;
      for (std::size_t k = 1; k < len; ++k) cp = cp << 6 | (byte(i + k) & 0x3f);
      Put(out, cp);
      i += len - 1;
    } else {  // US-ASCII
      Escape(out, "\\x%02x", b);
    }
  }
  return out + '"';
}

}  // namespace revkit::backend
