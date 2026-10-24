// Property lists: XML and binary (bplist00), as CoreFoundation's
// CFPropertyList.c and CFBinaryPList.c lay them out (their public format;
// no code is taken from them), bounded for hostile input.

#include "revkit/apple/plist.hh"

#include "text.hh"

#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>

namespace revkit::apple {

// ---- Value -------------------------------------------------------------------

const Value *Value::get(std::string_view key) const {
  if (type != Type::dict) return nullptr;
  for (auto it = dict.rbegin(); it != dict.rend(); ++it)
    if (it->key == key) return &it->value;
  return nullptr;
}

std::optional<std::int64_t> Value::as_int() const {
  if (type != Type::integer) return std::nullopt;
  if (big) return std::nullopt;
  return integer;
}

std::string Value::string_at(std::string_view key) const {
  const Value *v = get(key);
  return v && v->type == Type::string ? v->bytes : std::string();
}

std::vector<std::string> Value::strings_at(std::string_view key) const {
  std::vector<std::string> out;
  const Value *v = get(key);
  if (!v) return out;
  if (v->type == Type::string) out.push_back(v->bytes);
  else if (v->type == Type::array)
    for (const Value &x : v->array)
      if (x.type == Type::string) out.push_back(x.bytes);
  return out;
}

Value Value::make_string(std::string s) {
  Value v;
  v.type = Type::string;
  v.bytes = std::move(s);
  return v;
}

Value Value::make_int(std::int64_t i) {
  Value v;
  v.type = Type::integer;
  v.integer = i;
  return v;
}

Value Value::make_bool(bool b) {
  Value v;
  v.type = Type::boolean;
  v.boolean = b;
  return v;
}

namespace {

// Counts what a parse makes against the limits.
struct Budget {
  const Limits &limits;
  std::uint64_t values = 0;
  std::uint64_t bytes = 0;
  void value() {
    if (++values > limits.max_values)
      throw LimitError("more than " + std::to_string(limits.max_values) + " values in the property list");
  }
  void charge(std::uint64_t n) {
    bytes += n;
    if (bytes > limits.max_value_bytes)
      throw LimitError("the property list's strings and data pass " + std::to_string(limits.max_value_bytes >> 20) +
                       " MiB");
  }
};

// ---- dates -------------------------------------------------------------------

// Days since 1970-01-01 of a civil date, and back (Howard Hinnant's
// algorithms, public domain).
std::int64_t days_from_civil(std::int64_t y, unsigned m, unsigned d) {
  y -= m <= 2;
  const std::int64_t era = (y >= 0 ? y : y - 399) / 400;
  const unsigned yoe = static_cast<unsigned>(y - era * 400);
  const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return era * 146097 + static_cast<std::int64_t>(doe) - 719468;
}

void civil_from_days(std::int64_t z, std::int64_t &y, unsigned &m, unsigned &d) {
  z += 719468;
  const std::int64_t era = (z >= 0 ? z : z - 146096) / 146097;
  const unsigned doe = static_cast<unsigned>(z - era * 146097);
  const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  y = static_cast<std::int64_t>(yoe) + era * 400;
  const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  const unsigned mp = (5 * doy + 2) / 153;
  d = doy - (153 * mp + 2) / 5 + 1;
  m = mp < 10 ? mp + 3 : mp - 9;
  y += m <= 2;
}

// ---- base64 ------------------------------------------------------------------

int b64_value(unsigned char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

// CoreFoundation's rule: characters outside the alphabet are ignored, '='
// ends the data, an incomplete last quartet gives what its bits make.
std::string base64_decode(std::string_view in) {
  std::string out;
  out.reserve(in.size() * 3 / 4);
  std::uint32_t acc = 0;
  int bits = 0;
  for (unsigned char c : in) {
    if (c == '=') break;
    const int v = b64_value(c);
    if (v < 0) continue;
    acc = (acc << 6) | static_cast<std::uint32_t>(v);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<char>((acc >> bits) & 0xff));
    }
  }
  return out;
}

std::string base64_encode(std::string_view in) {
  static const char *alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  std::size_t i = 0;
  for (; i + 3 <= in.size(); i += 3) {
    const std::uint32_t v = static_cast<std::uint8_t>(in[i]) << 16 | static_cast<std::uint8_t>(in[i + 1]) << 8 |
                            static_cast<std::uint8_t>(in[i + 2]);
    out += alphabet[v >> 18];
    out += alphabet[(v >> 12) & 63];
    out += alphabet[(v >> 6) & 63];
    out += alphabet[v & 63];
  }
  if (i < in.size()) {
    std::uint32_t v = static_cast<std::uint8_t>(in[i]) << 16;
    if (i + 1 < in.size()) v |= static_cast<std::uint8_t>(in[i + 1]) << 8;
    out += alphabet[v >> 18];
    out += alphabet[(v >> 12) & 63];
    out += i + 1 < in.size() ? alphabet[(v >> 6) & 63] : '=';
    out += '=';
  }
  return out;
}

// ---- XML ---------------------------------------------------------------------

class XmlReader {
 public:
  XmlReader(std::string_view text, Budget &budget) : s_(text), budget_(budget) {}

  Value document() {
    prolog();
    Value v;
    std::string name;
    bool empty = false;
    open_tag(name, empty);
    if (name == "plist") {
      if (empty) throw Error("an empty <plist/>");
      skip_misc();
      if (peek_close("plist")) {
        // <plist></plist>: no value, as CF reads it (an empty dictionary
        // would invent one).
        throw Error("a <plist> with no value");
      }
      std::string inner;
      bool inner_empty = false;
      open_tag(inner, inner_empty);
      v = value(inner, inner_empty, 1);
      skip_misc();
      close_tag("plist");
    } else {
      v = value(name, empty, 1);
    }
    skip_misc();
    if (pos_ != s_.size()) throw error("text after the property list");
    return v;
  }

 private:
  Error error(const std::string &what) const { return Error(what + " at byte " + std::to_string(pos_)); }

  bool starts(std::string_view p) const { return s_.substr(pos_, p.size()) == p; }

  void skip_space() {
    while (pos_ < s_.size() && (s_[pos_] == ' ' || s_[pos_] == '\t' || s_[pos_] == '\r' || s_[pos_] == '\n')) ++pos_;
  }

  void skip_until(std::string_view end, const char *what) {
    const std::size_t at = s_.find(end, pos_);
    if (at == std::string_view::npos) throw error(std::string("an unterminated ") + what);
    pos_ = at + end.size();
  }

  // White space, comments and processing instructions.
  void skip_misc() {
    for (;;) {
      skip_space();
      if (starts("<!--")) skip_until("-->", "comment");
      else if (starts("<?")) skip_until("?>", "processing instruction");
      else return;
    }
  }

  void prolog() {
    for (;;) {
      skip_misc();
      if (starts("<!DOCTYPE")) {
        // Skipped, internal subset included; its entities are never used
        // (only the predefined ones and character references are).
        int depth = 0;
        while (pos_ < s_.size()) {
          const char c = s_[pos_++];
          if (c == '[') ++depth;
          else if (c == ']') --depth;
          else if (c == '>' && depth <= 0) break;
        }
        if (pos_ >= s_.size()) throw error("an unterminated DOCTYPE");
        continue;
      }
      return;
    }
  }

  static bool name_char(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-' || c == '.' || c == ':';
  }

  // "<name attr=...>" or "<name .../>": the name, attributes skipped.
  void open_tag(std::string &name, bool &empty) {
    skip_misc();
    if (pos_ >= s_.size() || s_[pos_] != '<') throw error("expected an element");
    ++pos_;
    const std::size_t start = pos_;
    while (pos_ < s_.size() && name_char(s_[pos_])) ++pos_;
    name.assign(s_.substr(start, pos_ - start));
    if (name.empty()) throw error("expected an element name");
    for (;;) {
      skip_space();
      if (pos_ >= s_.size()) throw error("an unterminated <" + name + ">");
      if (s_[pos_] == '>') {
        ++pos_;
        empty = false;
        return;
      }
      if (starts("/>")) {
        pos_ += 2;
        empty = true;
        return;
      }
      // An attribute: name="value" or name='value'.
      const std::size_t a = pos_;
      while (pos_ < s_.size() && name_char(s_[pos_])) ++pos_;
      if (pos_ == a) throw error("a malformed attribute in <" + name + ">");
      skip_space();
      if (pos_ >= s_.size() || s_[pos_] != '=') throw error("a malformed attribute in <" + name + ">");
      ++pos_;
      skip_space();
      if (pos_ >= s_.size() || (s_[pos_] != '"' && s_[pos_] != '\'')) throw error("an unquoted attribute");
      const char q = s_[pos_++];
      const std::size_t e = s_.find(q, pos_);
      if (e == std::string_view::npos) throw error("an unterminated attribute");
      pos_ = e + 1;
    }
  }

  bool peek_close(std::string_view name) const {
    if (!starts("</")) return false;
    return s_.substr(pos_ + 2, name.size()) == name;
  }

  void close_tag(std::string_view name) {
    skip_misc();
    if (!starts("</") || s_.substr(pos_ + 2, name.size()) != name) throw error("expected </" + std::string(name) + ">");
    pos_ += 2 + name.size();
    skip_space();
    if (pos_ >= s_.size() || s_[pos_] != '>') throw error("a malformed </" + std::string(name) + ">");
    ++pos_;
  }

  // Character data up to "</name>": entities and character references
  // decoded, CDATA kept as it is, comments dropped; another element in it
  // is an error.
  std::string text(std::string_view name) {
    std::string out;
    for (;;) {
      if (pos_ >= s_.size()) throw error("an unterminated <" + std::string(name) + ">");
      const char c = s_[pos_];
      if (c == '<') {
        if (starts("<![CDATA[")) {
          pos_ += 9;
          const std::size_t e = s_.find("]]>", pos_);
          if (e == std::string_view::npos) throw error("an unterminated CDATA section");
          out.append(s_.substr(pos_, e - pos_));
          pos_ = e + 3;
          continue;
        }
        if (starts("<!--")) {
          skip_until("-->", "comment");
          continue;
        }
        close_tag(name);
        budget_.charge(out.size());
        return out;
      }
      if (c == '&') {
        entity(out);
        continue;
      }
      out.push_back(c);
      ++pos_;
    }
  }

  void entity(std::string &out) {
    const std::size_t e = s_.find(';', pos_);
    if (e == std::string_view::npos || e - pos_ > 12) throw error("a malformed entity");
    const std::string_view ent = s_.substr(pos_ + 1, e - pos_ - 1);
    pos_ = e + 1;
    if (ent == "lt") out += '<';
    else if (ent == "gt") out += '>';
    else if (ent == "amp") out += '&';
    else if (ent == "quot") out += '"';
    else if (ent == "apos") out += '\'';
    else if (!ent.empty() && ent[0] == '#') {
      std::uint32_t cp = 0;
      const bool hex = ent.size() > 1 && (ent[1] == 'x' || ent[1] == 'X');
      std::string_view digits = ent.substr(hex ? 2 : 1);
      if (digits.empty()) throw error("a malformed character reference");
      for (char d : digits) {
        int v;
        if (d >= '0' && d <= '9') v = d - '0';
        else if (hex && d >= 'a' && d <= 'f') v = d - 'a' + 10;
        else if (hex && d >= 'A' && d <= 'F') v = d - 'A' + 10;
        else throw error("a malformed character reference");
        cp = cp * (hex ? 16 : 10) + static_cast<std::uint32_t>(v);
        if (cp > 0x10ffff) throw error("a character reference past U+10FFFF");
      }
      detail::append_utf8(out, cp);
    } else {
      throw error("an unknown entity &" + std::string(ent) + ";");
    }
  }

  static std::string_view trim(std::string_view t) {
    while (!t.empty() && std::isspace(static_cast<unsigned char>(t.front()))) t.remove_prefix(1);
    while (!t.empty() && std::isspace(static_cast<unsigned char>(t.back()))) t.remove_suffix(1);
    return t;
  }

  Value integer(std::string_view raw) {
    std::string_view t = trim(raw);
    bool neg = false;
    if (!t.empty() && (t[0] == '-' || t[0] == '+')) {
      neg = t[0] == '-';
      t.remove_prefix(1);
    }
    unsigned base = 10;
    if (t.size() > 2 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X')) {
      base = 16;
      t.remove_prefix(2);
    }
    if (t.empty()) throw error("an empty <integer>");
    std::uint64_t v = 0;
    for (char c : t) {
      unsigned d;
      if (c >= '0' && c <= '9') d = static_cast<unsigned>(c - '0');
      else if (base == 16 && c >= 'a' && c <= 'f') d = static_cast<unsigned>(c - 'a' + 10);
      else if (base == 16 && c >= 'A' && c <= 'F') d = static_cast<unsigned>(c - 'A' + 10);
      else throw error("a malformed <integer> \"" + std::string(raw.substr(0, 40)) + "\"");
      if (v > (std::numeric_limits<std::uint64_t>::max() - d) / base) throw error("an <integer> out of range");
      v = v * base + d;
    }
    Value out;
    out.type = Value::Type::integer;
    if (neg) {
      if (v > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) + 1)
        throw error("an <integer> out of range");
      out.integer = v == static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) + 1
                        ? std::numeric_limits<std::int64_t>::min()
                        : -static_cast<std::int64_t>(v);
    } else if (v > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
      out.big = true;
      out.unsigned_value = v;
    } else {
      out.integer = static_cast<std::int64_t>(v);
    }
    return out;
  }

  Value real(std::string_view raw) {
    std::string t(trim(raw));
    Value out;
    out.type = Value::Type::real;
    std::string lower;
    for (char c : t) lower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (lower == "nan") out.real = std::numeric_limits<double>::quiet_NaN();
    else if (lower == "inf" || lower == "+inf" || lower == "infinity" || lower == "+infinity")
      out.real = std::numeric_limits<double>::infinity();
    else if (lower == "-inf" || lower == "-infinity")
      out.real = -std::numeric_limits<double>::infinity();
    else {
      if (t.empty()) throw error("an empty <real>");
      char *end = nullptr;
      out.real = std::strtod(t.c_str(), &end);
      if (end != t.c_str() + t.size()) throw error("a malformed <real> \"" + t.substr(0, 40) + "\"");
    }
    return out;
  }

  Value value(const std::string &name, bool empty, std::uint32_t depth) {
    if (depth > budget_.limits.max_depth)
      throw LimitError("the property list nests deeper than " + std::to_string(budget_.limits.max_depth));
    budget_.value();
    Value v;
    if (name == "dict") {
      v.type = Value::Type::dict;
      if (empty) return v;
      for (;;) {
        skip_misc();
        if (peek_close("dict")) {
          close_tag("dict");
          detail::dedupe(v.dict);
          return v;
        }
        std::string k;
        bool kempty = false;
        open_tag(k, kempty);
        if (k != "key") throw error("expected <key> in a <dict>, found <" + k + ">");
        std::string key = kempty ? std::string() : text("key");
        std::string vn;
        bool vempty = false;
        open_tag(vn, vempty);
        v.dict.push_back(DictEntry{std::move(key), value(vn, vempty, depth + 1)});
      }
    }
    if (name == "array") {
      v.type = Value::Type::array;
      if (empty) return v;
      for (;;) {
        skip_misc();
        if (peek_close("array")) {
          close_tag("array");
          return v;
        }
        std::string n;
        bool e = false;
        open_tag(n, e);
        v.array.push_back(value(n, e, depth + 1));
      }
    }
    if (name == "string" || name == "ustring") {
      v.type = Value::Type::string;
      if (!empty) v.bytes = text(name);
      return v;
    }
    if (name == "true" || name == "false") {
      v.type = Value::Type::boolean;
      v.boolean = name == "true";
      if (!empty) {
        skip_space();
        close_tag(name);
      }
      return v;
    }
    if (name == "integer") {
      if (empty) throw error("an empty <integer/>");
      return integer(text(name));
    }
    if (name == "real") {
      if (empty) throw error("an empty <real/>");
      return real(text(name));
    }
    if (name == "date") {
      if (empty) throw error("an empty <date/>");
      const std::string t = text(name);
      auto d = parse_iso8601(trim(t));
      if (!d) throw error("a malformed <date> \"" + t.substr(0, 40) + "\"");
      v.type = Value::Type::date;
      v.real = *d;
      return v;
    }
    if (name == "data") {
      v.type = Value::Type::data;
      if (!empty) v.bytes = base64_decode(text(name));
      return v;
    }
    throw error("an unknown element <" + name + ">");
  }

  std::string_view s_;
  std::size_t pos_ = 0;
  Budget &budget_;
};

// ---- binary ------------------------------------------------------------------

class BinaryReader {
 public:
  BinaryReader(std::span<const std::byte> b, Budget &budget) : b_(b), budget_(budget) {}

  Value document() {
    if (b_.size() < 8 + 32) throw Error("a binary property list shorter than its header and trailer");
    if (std::memcmp(b_.data(), "bplist00", 8) != 0) throw Error("not a bplist00 property list");
    const std::size_t t = b_.size() - 32;
    offset_size_ = u8(t + 6);
    ref_size_ = u8(t + 7);
    count_ = be(t + 8, 8);
    const std::uint64_t top = be(t + 16, 8);
    table_ = be(t + 24, 8);
    if (offset_size_ < 1 || offset_size_ > 8 || ref_size_ < 1 || ref_size_ > 8)
      throw Error("a binary property list trailer with bad integer sizes");
    if (count_ == 0 || top >= count_) throw Error("a binary property list trailer with a bad top object");
    if (table_ < 9 || table_ > t || (t - table_) / offset_size_ < count_)
      throw Error("a binary property list offset table outside the file");
    on_path_.assign(static_cast<std::size_t>(count_), false);
    return object(top, 1);
  }

 private:
  std::uint8_t u8(std::uint64_t at) const {
    if (at >= b_.size()) throw Error("a binary property list read past its end");
    return static_cast<std::uint8_t>(b_[static_cast<std::size_t>(at)]);
  }
  std::uint64_t be(std::uint64_t at, unsigned n) const {
    if (at > b_.size() || n > b_.size() - at) throw Error("a binary property list read past its end");
    std::uint64_t v = 0;
    for (unsigned i = 0; i < n; ++i) v = v << 8 | static_cast<std::uint8_t>(b_[static_cast<std::size_t>(at + i)]);
    return v;
  }

  std::uint64_t offset_of(std::uint64_t obj) const {
    const std::uint64_t off = be(table_ + obj * offset_size_, offset_size_);
    if (off < 8 || off >= table_) throw Error("a binary property list object outside the object area");
    return off;
  }

  // An object's count: the marker's low nibble, or the integer after it.
  std::uint64_t length(std::uint64_t &at, std::uint8_t marker) const {
    const unsigned low = marker & 0x0f;
    if (low != 0x0f) return low;
    const std::uint8_t m = u8(at);
    if ((m & 0xf0) != 0x10) throw Error("a binary property list length that isn't an integer");
    const unsigned n = 1u << (m & 0x0f);
    if (n > 8) throw Error("a binary property list length wider than 64 bits");
    const std::uint64_t v = be(at + 1, n);
    at += 1 + n;
    return v;
  }

  std::uint64_t ref(std::uint64_t at) const {
    const std::uint64_t r = be(at, ref_size_);
    if (r >= count_) throw Error("a binary property list reference past its object count");
    return r;
  }

  // n elements of `each` bytes at `at`, inside the object area.
  void fits(std::uint64_t at, std::uint64_t n, std::uint64_t each) const {
    if (each != 0 && n > (table_ - std::min(at, table_)) / each)
      throw Error("a binary property list object runs past the object area");
  }

  Value object(std::uint64_t obj, std::uint32_t depth) {
    if (depth > budget_.limits.max_depth)
      throw LimitError("the property list nests deeper than " + std::to_string(budget_.limits.max_depth));
    if (on_path_[static_cast<std::size_t>(obj)]) throw Error("a binary property list whose objects form a cycle");
    budget_.value();
    std::uint64_t at = offset_of(obj);
    const std::uint8_t marker = u8(at++);
    Value v;
    switch (marker >> 4) {
      case 0x0:
        if (marker == 0x00) return v;  // null
        if (marker == 0x08 || marker == 0x09) {
          v.type = Value::Type::boolean;
          v.boolean = marker == 0x09;
          return v;
        }
        throw Error("an unknown binary property list marker " + std::to_string(marker));
      case 0x1: {
        const unsigned n = 1u << (marker & 0x0f);
        v.type = Value::Type::integer;
        if (n <= 4) {
          v.integer = static_cast<std::int64_t>(be(at, n));  // 1, 2 and 4 bytes are unsigned
        } else if (n == 8) {
          const std::uint64_t u = be(at, 8);
          v.integer = static_cast<std::int64_t>(u);  // signed
        } else if (n == 16) {
          // 128-bit: CoreFoundation writes uint64 values past INT64_MAX so,
          // the high half zero.
          const std::uint64_t hi = be(at, 8), lo = be(at + 8, 8);
          if (hi == 0 && lo > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
            v.big = true;
            v.unsigned_value = lo;
          } else {
            v.integer = static_cast<std::int64_t>(lo);
          }
        } else {
          throw Error("a binary property list integer wider than 128 bits");
        }
        return v;
      }
      case 0x2: {
        v.type = Value::Type::real;
        const unsigned n = 1u << (marker & 0x0f);
        if (n == 4) {
          const std::uint32_t bits = static_cast<std::uint32_t>(be(at, 4));
          float f;
          std::memcpy(&f, &bits, 4);
          v.real = f;
        } else if (n == 8) {
          const std::uint64_t bits = be(at, 8);
          std::memcpy(&v.real, &bits, 8);
        } else {
          throw Error("a binary property list real that isn't 4 or 8 bytes");
        }
        return v;
      }
      case 0x3: {
        if (marker != 0x33) throw Error("a binary property list date that isn't 8 bytes");
        v.type = Value::Type::date;
        const std::uint64_t bits = be(at, 8);
        std::memcpy(&v.real, &bits, 8);
        return v;
      }
      case 0x4: {
        const std::uint64_t n = length(at, marker);
        fits(at, n, 1);
        budget_.charge(n);
        v.type = Value::Type::data;
        v.bytes.assign(reinterpret_cast<const char *>(b_.data() + at), static_cast<std::size_t>(n));
        return v;
      }
      case 0x5: {
        // ASCII; bytes past 0x7f read as Latin-1, as CF's MacRoman-free
        // reader would show them.
        const std::uint64_t n = length(at, marker);
        fits(at, n, 1);
        budget_.charge(n * 2);
        v.type = Value::Type::string;
        for (std::uint64_t i = 0; i < n; ++i) detail::append_utf8(v.bytes, u8(at + i));
        return v;
      }
      case 0x6: {
        const std::uint64_t n = length(at, marker);
        fits(at, n, 2);
        budget_.charge(n * 3);
        v.type = Value::Type::string;
        std::vector<std::uint16_t> units(static_cast<std::size_t>(n));
        for (std::uint64_t i = 0; i < n; ++i) units[static_cast<std::size_t>(i)] = static_cast<std::uint16_t>(be(at + 2 * i, 2));
        v.bytes = detail::utf16_to_utf8(units);
        return v;
      }
      case 0x7: {
        // UTF-8 (bplist01 and later write it; accepted here too).
        const std::uint64_t n = length(at, marker);
        fits(at, n, 1);
        budget_.charge(n);
        v.type = Value::Type::string;
        v.bytes = detail::valid_utf8(std::string_view(reinterpret_cast<const char *>(b_.data() + at), static_cast<std::size_t>(n)));
        return v;
      }
      case 0x8: {
        const unsigned n = (marker & 0x0f) + 1;
        v.type = Value::Type::uid;
        v.uid = be(at, n);
        return v;
      }
      case 0xa:
      case 0xc: {
        // An array, or a set (read as an array).
        const std::uint64_t n = length(at, marker);
        fits(at, n, ref_size_);
        v.type = Value::Type::array;
        on_path_[static_cast<std::size_t>(obj)] = true;
        v.array.reserve(static_cast<std::size_t>(std::min<std::uint64_t>(n, 4096)));
        for (std::uint64_t i = 0; i < n; ++i) v.array.push_back(object(ref(at + i * ref_size_), depth + 1));
        on_path_[static_cast<std::size_t>(obj)] = false;
        return v;
      }
      case 0xd: {
        const std::uint64_t n = length(at, marker);
        if (n > std::numeric_limits<std::uint64_t>::max() / 2) throw Error("a binary property list dictionary too large");
        fits(at, n * 2, ref_size_);
        v.type = Value::Type::dict;
        on_path_[static_cast<std::size_t>(obj)] = true;
        v.dict.reserve(static_cast<std::size_t>(std::min<std::uint64_t>(n, 4096)));
        for (std::uint64_t i = 0; i < n; ++i) {
          Value k = object(ref(at + i * ref_size_), depth + 1);
          if (k.type != Value::Type::string) throw Error("a binary property list dictionary key that isn't a string");
          v.dict.push_back(DictEntry{std::move(k.bytes), object(ref(at + (n + i) * ref_size_), depth + 1)});
        }
        on_path_[static_cast<std::size_t>(obj)] = false;
        detail::dedupe(v.dict);
        return v;
      }
      default:
        throw Error("an unknown binary property list marker " + std::to_string(marker));
    }
  }

  std::span<const std::byte> b_;
  Budget &budget_;
  unsigned offset_size_ = 0, ref_size_ = 0;
  std::uint64_t count_ = 0, table_ = 0;
  std::vector<bool> on_path_;
};

// The text of an XML plist as UTF-8: a UTF-8 byte-order mark dropped,
// UTF-16 (with its mark) converted.
std::string xml_text(std::span<const std::byte> b) {
  auto u = [&](std::size_t i) { return static_cast<std::uint8_t>(b[i]); };
  if (b.size() >= 2 && ((u(0) == 0xff && u(1) == 0xfe) || (u(0) == 0xfe && u(1) == 0xff))) {
    const bool le = u(0) == 0xff;
    std::vector<std::uint16_t> units;
    units.reserve(b.size() / 2);
    for (std::size_t i = 2; i + 1 < b.size(); i += 2)
      units.push_back(static_cast<std::uint16_t>(le ? (u(i) | u(i + 1) << 8) : (u(i) << 8 | u(i + 1))));
    return detail::utf16_to_utf8(units);
  }
  std::size_t start = 0;
  if (b.size() >= 3 && u(0) == 0xef && u(1) == 0xbb && u(2) == 0xbf) start = 3;
  return std::string(reinterpret_cast<const char *>(b.data() + start), b.size() - start);
}

}  // namespace

std::optional<Format> sniff(std::span<const std::byte> head) {
  if (head.size() >= 8 && std::memcmp(head.data(), "bplist00", 8) == 0) return Format::binary;
  const std::string text = xml_text(head.first(std::min<std::size_t>(head.size(), 4096)));
  std::size_t i = 0;
  while (i < text.size() && std::isspace(static_cast<unsigned char>(text[i]))) ++i;
  if (text.compare(i, 1, "<") != 0) return std::nullopt;
  if (text.find("<plist", i) != std::string::npos) return Format::xml;
  return std::nullopt;
}

Value parse_xml(std::string_view text, const Limits &limits, std::uint64_t *values) {
  if (text.size() > limits.max_input)
    throw LimitError("a property list larger than " + std::to_string(limits.max_input >> 20) + " MiB");
  Budget budget{limits};
  XmlReader r(text, budget);
  Value v = r.document();
  if (values) *values = budget.values;
  return v;
}

Value parse_binary(std::span<const std::byte> bytes, const Limits &limits, std::uint64_t *values) {
  if (bytes.size() > limits.max_input)
    throw LimitError("a property list larger than " + std::to_string(limits.max_input >> 20) + " MiB");
  Budget budget{limits};
  BinaryReader r(bytes, budget);
  Value v = r.document();
  if (values) *values = budget.values;
  return v;
}

Parsed parse(std::span<const std::byte> bytes, const Limits &limits) {
  if (bytes.size() > limits.max_input)
    throw LimitError("a property list larger than " + std::to_string(limits.max_input >> 20) + " MiB");
  Parsed p;
  if (bytes.size() >= 8 && std::memcmp(bytes.data(), "bplist", 6) == 0) {
    p.format = Format::binary;
    p.root = parse_binary(bytes, limits, &p.values);
    return p;
  }
  const auto f = sniff(bytes);
  if (!f) throw Error("not a property list (XML or bplist00; OpenStep and JSON ones aren't read)");
  p.format = Format::xml;
  p.root = parse_xml(xml_text(bytes), limits, &p.values);
  return p;
}

std::string iso8601(double t) {
  if (!std::isfinite(t)) return "";
  const double unix_time = std::floor(t + kAbsoluteTimeEpoch);
  if (unix_time < -62135596800.0 || unix_time > 253402300799.0) return "";  // years 1 to 9999
  const auto secs = static_cast<std::int64_t>(unix_time);
  std::int64_t days = secs / 86400, rem = secs % 86400;
  if (rem < 0) {
    rem += 86400;
    --days;
  }
  std::int64_t y;
  unsigned m, d;
  civil_from_days(days, y, m, d);
  char buf[40];
  std::snprintf(buf, sizeof buf, "%04lld-%02u-%02uT%02lld:%02lld:%02lldZ", static_cast<long long>(y), m, d,
                static_cast<long long>(rem / 3600), static_cast<long long>(rem / 60 % 60), static_cast<long long>(rem % 60));
  return buf;
}

std::optional<double> parse_iso8601(std::string_view s) {
  // YYYY-MM-DDTHH:MM:SS, then optional fraction, then Z (or nothing).
  auto num = [&](std::size_t at, std::size_t n) -> std::optional<int> {
    if (at + n > s.size()) return std::nullopt;
    int v = 0;
    for (std::size_t i = at; i < at + n; ++i) {
      if (s[i] < '0' || s[i] > '9') return std::nullopt;
      v = v * 10 + (s[i] - '0');
    }
    return v;
  };
  auto y = num(0, 4), mo = num(5, 2), d = num(8, 2), h = num(11, 2), mi = num(14, 2), se = num(17, 2);
  if (!y || !mo || !d || !h || !mi || !se || s.size() < 19 || s[4] != '-' || s[7] != '-' || s[10] != 'T' ||
      s[13] != ':' || s[16] != ':')
    return std::nullopt;
  if (*mo < 1 || *mo > 12 || *d < 1 || *d > 31 || *h > 23 || *mi > 59 || *se > 59) return std::nullopt;
  std::size_t at = 19;
  double frac = 0;
  if (at < s.size() && s[at] == '.') {
    double scale = 0.1;
    ++at;
    while (at < s.size() && s[at] >= '0' && s[at] <= '9') {
      frac += (s[at] - '0') * scale;
      scale /= 10;
      ++at;
    }
  }
  if (at < s.size() && s[at] == 'Z') ++at;
  if (at != s.size()) return std::nullopt;
  const std::int64_t days = days_from_civil(*y, static_cast<unsigned>(*mo), static_cast<unsigned>(*d));
  const double unix_time = static_cast<double>(days * 86400 + *h * 3600 + *mi * 60 + *se) + frac;
  return unix_time - kAbsoluteTimeEpoch;
}

namespace {

void escape(std::string &out, std::string_view s) {
  for (char c : s) {
    switch (c) {
      case '<': out += "&lt;"; break;
      case '>': out += "&gt;"; break;
      case '&': out += "&amp;"; break;
      default: out += c;
    }
  }
}

void write_xml(std::string &out, const Value &v, int indent) {
  const std::string pad(static_cast<std::size_t>(indent), '\t');
  out += pad;
  switch (v.type) {
    case Value::Type::null: out += "<string></string>"; break;  // XML has no null
    case Value::Type::boolean: out += v.boolean ? "<true/>" : "<false/>"; break;
    case Value::Type::integer:
      out += "<integer>" + (v.big ? std::to_string(v.unsigned_value) : std::to_string(v.integer)) + "</integer>";
      break;
    case Value::Type::real: {
      char buf[64];
      if (std::isnan(v.real)) std::snprintf(buf, sizeof buf, "nan");
      else if (std::isinf(v.real)) std::snprintf(buf, sizeof buf, v.real > 0 ? "+infinity" : "-infinity");
      else std::snprintf(buf, sizeof buf, "%.17g", v.real);
      out += std::string("<real>") + buf + "</real>";
      break;
    }
    case Value::Type::date: out += "<date>" + iso8601(v.real) + "</date>"; break;
    case Value::Type::data: out += "<data>" + base64_encode(v.bytes) + "</data>"; break;
    case Value::Type::string:
      out += "<string>";
      escape(out, v.bytes);
      out += "</string>";
      break;
    case Value::Type::uid:
      out += "<dict>\n" + pad + "\t<key>CF$UID</key>\n" + pad + "\t<integer>" + std::to_string(v.uid) + "</integer>\n" +
             pad + "</dict>";
      break;
    case Value::Type::array:
      if (v.array.empty()) {
        out += "<array/>";
        break;
      }
      out += "<array>\n";
      for (const Value &x : v.array) write_xml(out, x, indent + 1);
      out += pad + "</array>";
      break;
    case Value::Type::dict:
      if (v.dict.empty()) {
        out += "<dict/>";
        break;
      }
      out += "<dict>\n";
      for (const DictEntry &e : v.dict) {
        out += pad + "\t<key>";
        escape(out, e.key);
        out += "</key>\n";
        write_xml(out, e.value, indent + 1);
      }
      out += pad + "</dict>";
      break;
  }
  out += '\n';
}

}  // namespace

std::string to_xml(const Value &v) {
  std::string out =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
      "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
      "<plist version=\"1.0\">\n";
  write_xml(out, v, 0);
  out += "</plist>\n";
  return out;
}

}  // namespace revkit::apple
