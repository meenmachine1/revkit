#include "json.hh"

#include <charconv>
#include <cmath>
#include <cstdio>

namespace rklift {

namespace {

constexpr char kDigits[] = "0123456789abcdef";

void escape_unit(std::string &out, std::uint32_t u) {
  out += "\\u";
  for (int shift = 12; shift >= 0; shift -= 4) out.push_back(kDigits[(u >> shift) & 0xf]);
}

// Appends a JSON string literal escaped like Python's json with
// ensure_ascii: non-ASCII as \uXXXX (surrogate pairs above the BMP).
// Invalid UTF-8 bytes become U+FFFD so the output is always valid.
void quote(std::string &out, std::string_view s) {
  out.push_back('"');
  std::size_t i = 0;
  while (i < s.size()) {
    auto c = static_cast<unsigned char>(s[i]);
    if (c < 0x80) {
      switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        default:
          if (c < 0x20) escape_unit(out, c);
          else out.push_back(static_cast<char>(c));
      }
      ++i;
      continue;
    }
    // Decode one UTF-8 sequence, rejecting overlongs and surrogates.
    std::size_t len = c >= 0xf0 && c <= 0xf4 ? 4 : c >= 0xe0 && c <= 0xef ? 3 : c >= 0xc2 && c <= 0xdf ? 2 : 0;
    std::uint32_t cp = len == 4 ? c & 0x07 : len == 3 ? c & 0x0f : c & 0x1f;
    bool ok = len != 0 && i + len <= s.size();
    for (std::size_t k = 1; ok && k < len; ++k) {
      auto cc = static_cast<unsigned char>(s[i + k]);
      ok = (cc & 0xc0) == 0x80;
      cp = (cp << 6) | (cc & 0x3f);
    }
    if (ok) {
      ok = (len == 3 && cp >= 0x800 && (cp < 0xd800 || cp > 0xdfff)) || (len == 4 && cp >= 0x10000 && cp <= 0x10ffff) ||
           len == 2;
    }
    if (!ok) {
      escape_unit(out, 0xfffd);
      ++i;
      continue;
    }
    if (cp >= 0x10000) {
      cp -= 0x10000;
      escape_unit(out, 0xd800 + (cp >> 10));
      escape_unit(out, 0xdc00 + (cp & 0x3ff));
    } else {
      escape_unit(out, cp);
    }
    i += len;
  }
  out.push_back('"');
}

}  // namespace

std::string hex(std::uint64_t v) {
  std::string s;
  append_hex(s, v);
  return s;
}

void append_hex(std::string &out, std::uint64_t v) {
  char buf[16];
  int n = 0;
  do {
    buf[n++] = kDigits[v & 0xf];
    v >>= 4;
  } while (v != 0);
  out += "0x";
  while (n > 0) out.push_back(buf[--n]);
}

void append_quoted(std::string &out, std::string_view s) { quote(out, s); }

namespace {
constexpr std::size_t kFlushBytes = std::size_t{1} << 20;
}

DocumentWriter::DocumentWriter(std::ostream &os) : os_(os) { buf_.reserve(kFlushBytes + (kFlushBytes >> 2)); }

void DocumentWriter::key(std::string_view k) {
  if (in_array_) throw JsonError("DocumentWriter: key inside an array");
  if (any_key_ && k <= std::string_view(last_key_)) throw JsonError("DocumentWriter: keys out of order");
  buf_ += any_key_ ? ",\n" : "{\n";
  any_key_ = true;
  last_key_ = k;
  quote(buf_, k);
  buf_.push_back(':');
}

void DocumentWriter::field(std::string_view k, const Json &value) {
  key(k);
  buf_ += value.compact();
  flush_if_full();
}

void DocumentWriter::begin_array(std::string_view k) {
  key(k);
  buf_.push_back('[');
  in_array_ = true;
  any_element_ = false;
}

std::string &DocumentWriter::element() {
  if (!in_array_) throw JsonError("DocumentWriter: element outside an array");
  flush_if_full();
  buf_ += any_element_ ? ",\n" : "\n";
  any_element_ = true;
  return buf_;
}

void DocumentWriter::end_array() {
  if (!in_array_) throw JsonError("DocumentWriter: no array to end");
  buf_ += any_element_ ? "\n]" : "]";
  in_array_ = false;
  flush_if_full();
}

bool DocumentWriter::finish() {
  if (in_array_) end_array();
  buf_ += any_key_ ? "\n}\n" : "{\n}\n";
  os_.write(buf_.data(), static_cast<std::streamsize>(buf_.size()));
  buf_.clear();
  os_.flush();
  return static_cast<bool>(os_);
}

void DocumentWriter::flush_if_full() {
  if (buf_.size() < kFlushBytes) return;
  os_.write(buf_.data(), static_cast<std::streamsize>(buf_.size()));
  buf_.clear();
}

void Json::write_compact(std::string &out) const {
  if (std::holds_alternative<std::nullptr_t>(v_)) {
    out += "null";
  } else if (const bool *b = std::get_if<bool>(&v_)) {
    out += *b ? "true" : "false";
  } else if (const std::int64_t *i = std::get_if<std::int64_t>(&v_)) {
    out += std::to_string(*i);
  } else if (const std::uint64_t *u = std::get_if<std::uint64_t>(&v_)) {
    out += std::to_string(*u);
  } else if (const double *d = std::get_if<double>(&v_)) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "%.17g", *d);
    out += buf;
  } else if (const std::string *s = std::get_if<std::string>(&v_)) {
    quote(out, *s);
  } else if (const Array *a = std::get_if<Array>(&v_)) {
    out.push_back('[');
    for (std::size_t k = 0; k < a->size(); ++k) {
      if (k != 0) out.push_back(',');
      (*a)[k].write_compact(out);
    }
    out.push_back(']');
  } else if (const Object *o = std::get_if<Object>(&v_)) {
    out.push_back('{');
    bool first = true;
    for (const auto &[key, value] : *o) {
      if (!first) out.push_back(',');
      first = false;
      quote(out, key);
      out.push_back(':');
      value.write_compact(out);
    }
    out.push_back('}');
  }
}

std::string Json::compact() const {
  std::string out;
  write_compact(out);
  return out;
}

void Json::write_document(std::ostream &os) const {
  const Object *o = std::get_if<Object>(&v_);
  if (o == nullptr) {
    os << compact() << '\n';
    return;
  }
  os << "{\n";
  std::size_t k = 0;
  for (const auto &[key, value] : *o) {
    const char *sep = ++k < o->size() ? "," : "";
    std::string q;
    quote(q, key);
    const Array *a = std::get_if<Array>(&value.v_);
    if (a == nullptr) {
      os << q << ':' << value.compact() << sep << '\n';
    } else if (a->empty()) {
      os << q << ":[]" << sep << '\n';
    } else {
      os << q << ":[\n";
      for (std::size_t j = 0; j < a->size(); ++j) os << (*a)[j].compact() << (j + 1 < a->size() ? "," : "") << '\n';
      os << ']' << sep << '\n';
    }
  }
  os << "}\n";
}

namespace {

class Parser {
 public:
  explicit Parser(std::string_view s) : s_(s) {}

  Json document() {
    Json v = value();
    skip_ws();
    if (i_ != s_.size()) fail("trailing characters");
    return v;
  }

 private:
  [[noreturn]] void fail(const std::string &what) const {
    throw JsonError("JSON: " + what + " at offset " + std::to_string(i_));
  }
  void skip_ws() {
    while (i_ < s_.size() && (s_[i_] == ' ' || s_[i_] == '\n' || s_[i_] == '\r' || s_[i_] == '\t')) ++i_;
  }
  bool consume(char c) {
    skip_ws();
    if (i_ < s_.size() && s_[i_] == c) {
      ++i_;
      return true;
    }
    return false;
  }
  void expect(char c) {
    if (!consume(c)) fail(std::string("expected '") + c + "'");
  }
  bool literal(std::string_view word) {
    if (s_.substr(i_, word.size()) == word) {
      i_ += word.size();
      return true;
    }
    return false;
  }

  Json value() {
    skip_ws();
    if (i_ >= s_.size()) fail("unexpected end");
    char c = s_[i_];
    if (c == '{') return object();
    if (c == '[') return array();
    if (c == '"') return Json(string());
    if (literal("true")) return Json(true);
    if (literal("false")) return Json(false);
    if (literal("null")) return Json(nullptr);
    return number();
  }

  Json object() {
    ++i_;
    Json::Object o;
    if (consume('}')) return Json(std::move(o));
    for (;;) {
      skip_ws();
      if (i_ >= s_.size() || s_[i_] != '"') fail("expected key");
      std::string key = string();
      expect(':');
      o.insert_or_assign(std::move(key), value());
      if (consume(',')) continue;
      expect('}');
      return Json(std::move(o));
    }
  }

  Json array() {
    ++i_;
    Json::Array a;
    if (consume(']')) return Json(std::move(a));
    for (;;) {
      a.push_back(value());
      if (consume(',')) continue;
      expect(']');
      return Json(std::move(a));
    }
  }

  static void put_utf8(std::string &out, std::uint32_t cp) {
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

  std::uint32_t hex4() {
    if (i_ + 4 > s_.size()) fail("short \\u escape");
    std::uint32_t v = 0;
    auto r = std::from_chars(s_.data() + i_, s_.data() + i_ + 4, v, 16);
    if (r.ptr != s_.data() + i_ + 4) fail("bad \\u escape");
    i_ += 4;
    return v;
  }

  std::string string() {
    ++i_;  // opening quote
    std::string out;
    for (;;) {
      std::size_t j = i_;
      while (j < s_.size() && s_[j] != '"' && s_[j] != '\\') ++j;
      out.append(s_.substr(i_, j - i_));
      i_ = j;
      if (i_ >= s_.size()) fail("unterminated string");
      if (s_[i_] == '"') {
        ++i_;
        return out;
      }
      ++i_;  // backslash
      if (i_ >= s_.size()) fail("bad escape");
      char e = s_[i_++];
      switch (e) {
        case '"': out.push_back('"'); break;
        case '\\': out.push_back('\\'); break;
        case '/': out.push_back('/'); break;
        case 'b': out.push_back('\b'); break;
        case 'f': out.push_back('\f'); break;
        case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break;
        case 't': out.push_back('\t'); break;
        case 'u': {
          std::uint32_t cp = hex4();
          if (cp >= 0xd800 && cp < 0xdc00 && s_.substr(i_, 2) == "\\u") {
            i_ += 2;
            std::uint32_t lo = hex4();
            if (lo >= 0xdc00 && lo < 0xe000) cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
          }
          put_utf8(out, cp);
          break;
        }
        default: fail("bad escape");
      }
    }
  }

  Json number() {
    std::size_t start = i_;
    bool negative = false;
    if (i_ < s_.size() && s_[i_] == '-') {
      negative = true;
      ++i_;
    }
    bool fraction = false;
    while (i_ < s_.size()) {
      char c = s_[i_];
      if (c >= '0' && c <= '9') ++i_;
      else if (c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') {
        fraction = true;
        ++i_;
      } else break;
    }
    std::string_view text = s_.substr(start, i_ - start);
    if (text.empty() || text == "-") fail("bad value");
    if (!fraction) {
      if (negative) {
        std::int64_t v = 0;
        auto r = std::from_chars(text.data(), text.data() + text.size(), v);
        if (r.ec == std::errc()) return Json(v);
      } else {
        std::uint64_t v = 0;
        auto r = std::from_chars(text.data(), text.data() + text.size(), v);
        if (r.ec == std::errc()) {
          if (v <= static_cast<std::uint64_t>(INT64_MAX)) return Json(static_cast<std::int64_t>(v));
          return Json(v);
        }
      }
    }
    return Json(std::stod(std::string(text)));
  }

  std::string_view s_;
  std::size_t i_ = 0;
};

const Json kNull;

}  // namespace

Json Json::parse(std::string_view text) { return Parser(text).document(); }

bool Json::is_number() const {
  return std::holds_alternative<std::int64_t>(v_) || std::holds_alternative<std::uint64_t>(v_) ||
         std::holds_alternative<double>(v_);
}

const Json::Object &Json::object() const {
  if (const Object *o = std::get_if<Object>(&v_)) return *o;
  throw JsonError("JSON: expected an object");
}

const Json::Array &Json::array() const {
  if (const Array *a = std::get_if<Array>(&v_)) return *a;
  throw JsonError("JSON: expected an array");
}

const std::string &Json::str() const {
  if (const std::string *s = std::get_if<std::string>(&v_)) return *s;
  throw JsonError("JSON: expected a string");
}

bool Json::boolean() const {
  if (const bool *b = std::get_if<bool>(&v_)) return *b;
  throw JsonError("JSON: expected a boolean");
}

std::int64_t Json::int64() const {
  if (const std::int64_t *i = std::get_if<std::int64_t>(&v_)) return *i;
  if (const std::uint64_t *u = std::get_if<std::uint64_t>(&v_)) return static_cast<std::int64_t>(*u);
  if (const double *d = std::get_if<double>(&v_)) return static_cast<std::int64_t>(*d);
  throw JsonError("JSON: expected a number");
}

std::uint64_t Json::uint64() const {
  if (const std::uint64_t *u = std::get_if<std::uint64_t>(&v_)) return *u;
  if (const std::int64_t *i = std::get_if<std::int64_t>(&v_)) return static_cast<std::uint64_t>(*i);
  throw JsonError("JSON: expected an integer");
}

const Json *Json::find(const std::string &key) const {
  const Object *o = std::get_if<Object>(&v_);
  if (o == nullptr) return nullptr;
  auto it = o->find(key);
  return it == o->end() ? nullptr : &it->second;
}

const Json &Json::operator[](const std::string &key) const {
  const Json *j = find(key);
  return j != nullptr ? *j : kNull;
}

std::uint64_t parse_hex_string(const std::string &s) {
  std::string_view v = s;
  if (v.starts_with("0x") || v.starts_with("0X")) v.remove_prefix(2);
  std::uint64_t out = 0;
  auto r = std::from_chars(v.data(), v.data() + v.size(), out, 16);
  if (v.empty() || r.ec != std::errc() || r.ptr != v.data() + v.size()) throw JsonError("bad hex value: " + s);
  return out;
}

}  // namespace rklift
