#include "search.h"

#include <re2/re2.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <vector>

namespace revkit::backend::search {
namespace {

// How far a regular expression's match may run past its chunk.
constexpr std::size_t kRegexReach = 4096;

bool IsHex(char c) { return std::isxdigit(static_cast<unsigned char>(c)) != 0; }
int HexVal(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  return std::tolower(static_cast<unsigned char>(c)) - 'a' + 10;
}
bool IsWild(char c) { return c == '?' || c == '.'; }
bool IsSpace(char c) { return std::isspace(static_cast<unsigned char>(c)) != 0; }
bool IsAsciiLetter(unsigned char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
unsigned char Lower(unsigned char c) { return c >= 'A' && c <= 'Z' ? static_cast<unsigned char>(c + 32) : c; }

void Push(Pattern &p, unsigned char v, unsigned char m = 0xff, bool fold = false) {
  p.value.push_back(static_cast<char>(v & m));
  p.mask.push_back(static_cast<char>(m));
  p.fold.push_back(fold ? 1 : 0);
}

// "48 8b ?? e8", "488b??e8", "4? ?f": whole bytes, a nibble each digit.
std::string ParseHex(const std::string &text, Pattern &out) {
  std::string digits;
  for (std::size_t i = 0; i < text.size(); ++i) {
    char c = text[i];
    if (IsSpace(c) || c == ',') {
      // A lone digit before a space is a byte with a leading zero ("a 0b").
      if (digits.size() % 2 == 1) digits.insert(digits.size() - 1, 1, '0');
      continue;
    }
    if (c == '0' && i + 1 < text.size() && (text[i + 1] == 'x' || text[i + 1] == 'X') && digits.size() % 2 == 0) {
      ++i;
      continue;
    }
    if (!IsHex(c) && !IsWild(c)) return std::string("not a hex digit or wildcard: '") + c + "'";
    digits.push_back(c);
  }
  if (digits.size() % 2 == 1) digits.insert(digits.size() - 1, 1, '0');
  if (digits.empty()) return "nothing to search for";
  for (std::size_t i = 0; i < digits.size(); i += 2) {
    unsigned char v = 0, m = 0;
    for (int k = 0; k < 2; ++k) {
      const char c = digits[i + k];
      v = static_cast<unsigned char>(v << 4);
      m = static_cast<unsigned char>(m << 4);
      if (!IsWild(c)) {
        v |= static_cast<unsigned char>(HexVal(c));
        m |= 0xf;
      }
    }
    Push(out, v, m);
  }
  return {};
}

// "10xx0101 11110000": 8 bits a byte; x, ? and . are either.
std::string ParseBinary(const std::string &text, Pattern &out) {
  std::string bits;
  for (char c : text) {
    if (IsSpace(c) || c == ',') {
      if (bits.size() % 8 != 0) return "each byte is 8 binary digits";
      continue;
    }
    if (c == 'X') c = 'x';
    if (c != '0' && c != '1' && c != 'x' && !IsWild(c)) return std::string("not a binary digit or wildcard: '") + c + "'";
    bits.push_back(c);
  }
  if (bits.empty()) return "nothing to search for";
  if (bits.size() % 8 != 0) return "each byte is 8 binary digits";
  for (std::size_t i = 0; i < bits.size(); i += 8) {
    unsigned char v = 0, m = 0;
    for (int k = 0; k < 8; ++k) {
      const char c = bits[i + k];
      v = static_cast<unsigned char>(v << 1);
      m = static_cast<unsigned char>(m << 1);
      if (c == '0' || c == '1') {
        m |= 1;
        if (c == '1') v |= 1;
      }
    }
    Push(out, v, m);
  }
  return {};
}

// UTF-8 to code points; false on malformed input.
bool DecodeUtf8(std::string_view s, std::size_t &i, std::uint32_t &cp) {
  const auto b = static_cast<unsigned char>(s[i]);
  if (b < 0x80) {
    cp = b;
    ++i;
    return true;
  }
  const int n = (b >> 5) == 6 ? 1 : (b >> 4) == 14 ? 2 : (b >> 3) == 30 ? 3 : -1;
  if (n < 0 || i + n >= s.size()) return false;
  cp = b & (0x3f >> n);
  for (int k = 1; k <= n; ++k) {
    const auto c = static_cast<unsigned char>(s[i + k]);
    if ((c >> 6) != 2) return false;
    cp = (cp << 6) | (c & 0x3f);
  }
  i += n + 1;
  return true;
}

void AppendUtf8(std::string &out, std::uint32_t cp) {
  if (cp < 0x80) {
    out.push_back(static_cast<char>(cp));
  } else if (cp < 0x800) {
    out.push_back(static_cast<char>(0xc0 | (cp >> 6)));
    out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
  } else if (cp < 0x10000) {
    out.push_back(static_cast<char>(0xe0 | (cp >> 12)));
    out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
    out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
  } else {
    out.push_back(static_cast<char>(0xf0 | (cp >> 18)));
    out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3f)));
    out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
    out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
  }
}

// One unit of a string query: a code point, or (\xHH in ASCII and UTF-8)
// a raw byte.
struct Unit {
  std::uint32_t value;
  bool raw_byte;
};

std::string ReadString(const std::string &text, bool escapes, std::vector<Unit> &out) {
  for (std::size_t i = 0; i < text.size();) {
    std::uint32_t cp;
    if (!DecodeUtf8(text, i, cp)) return "the query is not valid UTF-8";
    if (!escapes || cp != '\\') {
      out.push_back({cp, false});
      continue;
    }
    if (i >= text.size()) return "a backslash ends the query (\\\\ is a backslash)";
    const char e = text[i++];
    auto hex = [&](int n, std::uint32_t &v) {
      v = 0;
      int k = 0;
      for (; k < n && i < text.size() && IsHex(text[i]); ++k) v = v * 16 + HexVal(text[i++]);
      return k > 0;
    };
    std::uint32_t v;
    switch (e) {
      case 'n': out.push_back({'\n', false}); break;
      case 't': out.push_back({'\t', false}); break;
      case 'r': out.push_back({'\r', false}); break;
      case '0': out.push_back({0, false}); break;
      case '\\': out.push_back({'\\', false}); break;
      case '"': out.push_back({'"', false}); break;
      case '\'': out.push_back({'\'', false}); break;
      case 'x':
        if (!hex(2, v)) return "\\x needs hex digits";
        out.push_back({v, true});
        break;
      case 'u':
        if (!hex(4, v)) return "\\u needs hex digits";
        out.push_back({v, false});
        break;
      default: return std::string("unknown escape \\") + e;
    }
  }
  if (out.empty()) return "nothing to search for";
  return {};
}

std::string EncodeString(const pb::SearchMemoryRequest &req, bool big_endian, Pattern &out) {
  std::vector<Unit> units;
  if (auto e = ReadString(req.query(), req.escape_sequences(), units); !e.empty()) return e;
  const bool fold = !req.case_sensitive();
  for (const Unit &u : units) {
    switch (req.encoding()) {
      case pb::SEARCH_ENCODING_UNSPECIFIED:
      case pb::SEARCH_ENCODING_ASCII:
        if (u.value > 0xff) return "a character outside ASCII and Latin-1: search as UTF-8 or UTF-16";
        Push(out, static_cast<unsigned char>(u.value), 0xff, fold && IsAsciiLetter(static_cast<unsigned char>(u.value)));
        break;
      case pb::SEARCH_ENCODING_UTF8: {
        if (u.raw_byte) {
          Push(out, static_cast<unsigned char>(u.value));
          break;
        }
        std::string b;
        AppendUtf8(b, u.value);
        for (char c : b) Push(out, static_cast<unsigned char>(c), 0xff, fold && IsAsciiLetter(static_cast<unsigned char>(c)));
        break;
      }
      case pb::SEARCH_ENCODING_UTF16: {
        auto unit = [&](std::uint32_t w) {
          const auto lo = static_cast<unsigned char>(w & 0xff), hi = static_cast<unsigned char>(w >> 8);
          const bool letter = fold && w < 0x80 && IsAsciiLetter(lo);
          if (big_endian) {
            Push(out, hi);
            Push(out, lo, 0xff, letter);
          } else {
            Push(out, lo, 0xff, letter);
            Push(out, hi);
          }
        };
        if (u.value >= 0x10000) {
          const std::uint32_t v = u.value - 0x10000;
          unit(0xd800 + (v >> 10));
          unit(0xdc00 + (v & 0x3ff));
        } else {
          unit(u.value);
        }
        break;
      }
      default: return "unknown encoding";
    }
  }
  return {};
}

std::vector<std::string> Tokens(const std::string &text) {
  std::vector<std::string> out;
  std::string cur;
  for (char c : text) {
    if (IsSpace(c) || c == ',') {
      if (!cur.empty()) out.push_back(std::move(cur));
      cur.clear();
    } else {
      cur.push_back(c);
    }
  }
  if (!cur.empty()) out.push_back(std::move(cur));
  return out;
}

void PushValue(Pattern &out, std::uint64_t bits, unsigned size, bool big_endian) {
  for (unsigned k = 0; k < size; ++k) {
    const unsigned shift = 8 * (big_endian ? size - 1 - k : k);
    Push(out, static_cast<unsigned char>(bits >> shift));
  }
}

std::string EncodeDecimal(const pb::SearchMemoryRequest &req, bool big_endian, Pattern &out) {
  const unsigned size = req.value_size() == 0 ? 4 : req.value_size();
  if (size != 1 && size != 2 && size != 4 && size != 8) return "value_size is 1, 2, 4 or 8";
  const auto tokens = Tokens(req.query());
  if (tokens.empty()) return "nothing to search for";
  for (const std::string &t0 : tokens) {
    std::string t = t0;
    bool neg = false;
    if (!t.empty() && (t[0] == '-' || t[0] == '+')) {
      neg = t[0] == '-';
      t = t.substr(1);
    }
    int base = 10;
    if (t.size() > 2 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X')) {
      base = 16;
      t = t.substr(2);
    }
    if (t.empty() || !std::all_of(t.begin(), t.end(), [&](char c) { return base == 16 ? IsHex(c) : std::isdigit(static_cast<unsigned char>(c)) != 0; }))
      return "not a number: " + t0;
    errno = 0;
    char *end = nullptr;
    const unsigned long long mag = std::strtoull(t.c_str(), &end, base);
    if (errno == ERANGE) return t0 + " is too large";
    const std::uint64_t umax = size == 8 ? UINT64_MAX : (std::uint64_t{1} << (8 * size)) - 1;
    const std::uint64_t smin_mag = std::uint64_t{1} << (8 * size - 1);  // |most negative|
    if (neg) {
      if (req.unsigned_values()) return t0 + " is negative: values are unsigned";
      if (mag > smin_mag) return t0 + " doesn't fit " + std::to_string(size) + " byte" + (size == 1 ? "" : "s");
      PushValue(out, (~static_cast<std::uint64_t>(mag) + 1) & umax, size, big_endian);
    } else {
      // Signed values may be written in their unsigned form (255 for a
      // byte's -1): the bytes are the same.
      if (mag > umax) return t0 + " doesn't fit " + std::to_string(size) + " byte" + (size == 1 ? "" : "s");
      PushValue(out, mag, size, big_endian);
    }
  }
  return {};
}

std::string EncodeFloat(const pb::SearchMemoryRequest &req, bool big_endian, bool dbl, Pattern &out) {
  const auto tokens = Tokens(req.query());
  if (tokens.empty()) return "nothing to search for";
  for (const std::string &t : tokens) {
    errno = 0;
    char *end = nullptr;
    const double d = std::strtod(t.c_str(), &end);
    if (end == t.c_str() || *end != '\0') return "not a number: " + t;
    if (dbl) {
      std::uint64_t bits;
      std::memcpy(&bits, &d, 8);
      PushValue(out, bits, 8, big_endian);
    } else {
      const float f = static_cast<float>(d);
      if (std::isinf(f) && !std::isinf(d)) return t + " doesn't fit a float";
      std::uint32_t bits;
      std::memcpy(&bits, &f, 4);
      PushValue(out, bits, 4, big_endian);
    }
  }
  return {};
}

// A pattern scanner: candidates from an anchor position (memchr when it is
// a whole byte, else a table of the bytes it accepts), then every position.
class PatternMatcher final : public ByteMatcher {
 public:
  explicit PatternMatcher(Pattern p) : p_(std::move(p)) {
    const std::size_t n = p_.size();
    for (std::size_t i = 0; i < n; ++i) {
      v_.push_back(static_cast<unsigned char>(p_.value[i]));
      m_.push_back(static_cast<unsigned char>(p_.mask[i]));
      f_.push_back(p_.fold[i] != 0);
    }
    // The anchor: the first whole, unfolded byte (memchr finds it), else the
    // most selective position.
    anchor_ = n;
    for (std::size_t i = 0; i < n && anchor_ == n; ++i)
      if (m_[i] == 0xff && !f_[i]) anchor_ = i;
    whole_ = anchor_ != n;
    if (!whole_) {
      int best = 257;
      for (std::size_t i = 0; i < n; ++i) {
        int count = 0;
        for (int b = 0; b < 256; ++b) count += Accepts(i, static_cast<unsigned char>(b));
        if (count < best) best = count, anchor_ = i;
      }
      for (int b = 0; b < 256; ++b) table_[b] = Accepts(anchor_, static_cast<unsigned char>(b));
    }
  }

  bool Scan(const unsigned char *data, std::size_t len, std::size_t starts,
            const std::function<bool(std::size_t, std::size_t)> &fn) const override {
    const std::size_t n = v_.size();
    if (len < n) return true;
    const std::size_t last = std::min(starts, len - n + 1);  // exclusive
    std::size_t i = 0;
    while (i < last) {
      if (whole_) {
        const void *hit = std::memchr(data + i + anchor_, v_[anchor_], last - i);
        if (!hit) return true;
        i = static_cast<std::size_t>(static_cast<const unsigned char *>(hit) - data) - anchor_;
      } else {
        while (i < last && !table_[data[i + anchor_]]) ++i;
        if (i >= last) return true;
      }
      bool ok = true;
      for (std::size_t j = 0; ok && j < n; ++j) ok = Accepts(j, data[i + j]);
      if (ok && !fn(i, n)) return false;
      ++i;
    }
    return true;
  }
  std::size_t reach() const override { return v_.size() - 1; }

 private:
  bool Accepts(std::size_t j, unsigned char b) const {
    if (f_[j]) return Lower(b) == Lower(v_[j]);
    return (b & m_[j]) == v_[j];
  }

  Pattern p_;
  std::vector<unsigned char> v_, m_;
  std::vector<bool> f_;
  std::size_t anchor_ = 0;
  bool whole_ = false;
  bool table_[256] = {};
};

class RegexMatcher final : public ByteMatcher {
 public:
  explicit RegexMatcher(std::unique_ptr<re2::RE2> re) : re_(std::move(re)) {}
  bool Scan(const unsigned char *data, std::size_t len, std::size_t starts,
            const std::function<bool(std::size_t, std::size_t)> &fn) const override {
    const re2::StringPiece text(reinterpret_cast<const char *>(data), len);
    re2::StringPiece m;
    std::size_t pos = 0;
    while (pos < starts && pos < len) {
      if (!re_->Match(text, pos, len, re2::RE2::UNANCHORED, &m, 1)) return true;
      const auto at = static_cast<std::size_t>(m.data() - text.data());
      if (at >= starts) return true;
      if (!m.empty() && !fn(at, m.size())) return false;
      pos = at + 1;
    }
    return true;
  }
  std::size_t reach() const override { return kRegexReach; }

 private:
  std::unique_ptr<re2::RE2> re_;
};

bool WordChar(unsigned char c) { return std::isalnum(c) || c == '_' || c >= 0x80; }

}  // namespace

std::string Pattern::Display() const {
  static const char *kHex = "0123456789abcdef";
  std::string out;
  for (std::size_t i = 0; i < value.size(); ++i) {
    if (!out.empty()) out.push_back(' ');
    const auto v = static_cast<unsigned char>(value[i]), m = static_cast<unsigned char>(mask[i]);
    const bool hi = (m & 0xf0) == 0xf0 || (m & 0xf0) == 0, lo = (m & 0xf) == 0xf || (m & 0xf) == 0;
    if (!hi || !lo) {
      out += "[";
      out += kHex[v >> 4];
      out += kHex[v & 0xf];
      out += "/";
      out += kHex[m >> 4];
      out += kHex[m & 0xf];
      out += "]";
      continue;
    }
    out.push_back((m & 0xf0) ? kHex[v >> 4] : '?');
    out.push_back((m & 0x0f) ? kHex[v & 0xf] : '?');
  }
  return out;
}

std::string CompileMemoryQuery(const pb::SearchMemoryRequest &req, bool big_endian, Compiled &out) {
  out = {};
  const bool be = req.byte_order() == pb::ENDIANNESS_BIG || (req.byte_order() == pb::ENDIANNESS_UNSPECIFIED && big_endian);
  std::string err;
  switch (req.format()) {
    case pb::SEARCH_FORMAT_UNSPECIFIED:
    case pb::SEARCH_FORMAT_HEX: err = ParseHex(req.query(), out.pattern); break;
    case pb::SEARCH_FORMAT_BINARY: err = ParseBinary(req.query(), out.pattern); break;
    case pb::SEARCH_FORMAT_STRING: err = EncodeString(req, be, out.pattern); break;
    case pb::SEARCH_FORMAT_DECIMAL: err = EncodeDecimal(req, be, out.pattern); break;
    case pb::SEARCH_FORMAT_FLOAT: err = EncodeFloat(req, be, false, out.pattern); break;
    case pb::SEARCH_FORMAT_DOUBLE: err = EncodeFloat(req, be, true, out.pattern); break;
    case pb::SEARCH_FORMAT_REGEX:
      if (req.query().empty()) return "nothing to search for";
      out.is_regex = true;
      out.regex = req.query();
      return {};
    default: return "unknown format";
  }
  if (!err.empty()) return err;
  if (out.pattern.size() > 4096) return "the pattern is longer than 4096 bytes";
  if (std::all_of(out.pattern.mask.begin(), out.pattern.mask.end(), [](char m) { return m == 0; }))
    return "the pattern is all wildcards";
  return {};
}

std::unique_ptr<ByteMatcher> MakeByteMatcher(const Compiled &c, std::string &error) {
  if (!c.is_regex) return std::make_unique<PatternMatcher>(c.pattern);
  re2::RE2::Options o;
  o.set_encoding(re2::RE2::Options::EncodingLatin1);
  o.set_log_errors(false);
  o.set_max_mem(64 << 20);
  // The query arrives as UTF-8: as Latin-1 its characters are the bytes
  // they encode, which is what a non-ASCII literal should match.
  auto re = std::make_unique<re2::RE2>(c.regex, o);
  if (!re->ok()) {
    error = "bad regular expression: " + re->error();
    return nullptr;
  }
  if (re2::RE2::PartialMatch(re2::StringPiece(), *re)) {
    error = "the regular expression matches empty bytes: it needs at least one byte";
    return nullptr;
  }
  return std::make_unique<RegexMatcher>(std::move(re));
}

TextMatcher::~TextMatcher() = default;

std::unique_ptr<TextMatcher> TextMatcher::Make(const std::string &query, bool regex, bool case_sensitive, bool whole_word,
                                               std::string &error) {
  if (query.empty()) {
    error = "nothing to search for";
    return nullptr;
  }
  std::unique_ptr<TextMatcher> m(new TextMatcher());
  m->case_sensitive_ = case_sensitive;
  m->whole_word_ = whole_word;
  const bool ascii = std::all_of(query.begin(), query.end(), [](char c) { return static_cast<unsigned char>(c) < 0x80; });
  if (regex || (!case_sensitive && !ascii)) {
    re2::RE2::Options o;
    o.set_case_sensitive(case_sensitive);
    o.set_log_errors(false);
    o.set_max_mem(64 << 20);
    o.set_literal(!regex);
    m->re_ = std::make_unique<re2::RE2>(query, o);
    if (!m->re_->ok()) {
      error = "bad regular expression: " + m->re_->error();
      return nullptr;
    }
    if (re2::RE2::FullMatch("", *m->re_)) {
      error = "the regular expression matches empty text";
      return nullptr;
    }
    return m;
  }
  m->query_ = query;
  if (!case_sensitive)
    for (char &c : m->query_) c = static_cast<char>(Lower(static_cast<unsigned char>(c)));
  return m;
}

bool TextMatcher::FindPlain(std::string_view text, std::size_t from, std::size_t &start, std::size_t &length) const {
  std::size_t at;
  if (case_sensitive_) {
    at = text.find(query_, from);
  } else {
    thread_local std::string folded;
    folded.assign(text.data(), text.size());
    for (char &c : folded) c = static_cast<char>(Lower(static_cast<unsigned char>(c)));
    at = folded.find(query_, from);
  }
  if (at == std::string_view::npos) return false;
  start = at;
  length = query_.size();
  return true;
}

bool TextMatcher::FindRegex(std::string_view text, std::size_t from, std::size_t &start, std::size_t &length) const {
  re2::StringPiece m;
  const re2::StringPiece t(text.data(), text.size());
  while (from <= text.size()) {
    if (!re_->Match(t, from, text.size(), re2::RE2::UNANCHORED, &m, 1)) return false;
    start = static_cast<std::size_t>(m.data() - t.data());
    length = m.size();
    if (length > 0) return true;
    from = start + 1;  // skip an empty match (a regex like "a*")
  }
  return false;
}

bool TextMatcher::Find(std::string_view text, std::size_t &start, std::size_t &length) const {
  std::size_t from = 0;
  while (from <= text.size()) {
    if (!(re_ ? FindRegex(text, from, start, length) : FindPlain(text, from, start, length))) return false;
    if (!whole_word_) return true;
    const bool before = start > 0 && WordChar(static_cast<unsigned char>(text[start - 1])) &&
                        WordChar(static_cast<unsigned char>(text[start]));
    const std::size_t e = start + length;
    const bool after = e < text.size() && WordChar(static_cast<unsigned char>(text[e])) &&
                       WordChar(static_cast<unsigned char>(text[e - 1]));
    if (!before && !after) return true;
    from = start + 1;
  }
  return false;
}

}  // namespace revkit::backend::search
