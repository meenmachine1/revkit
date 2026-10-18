#include "json.hh"

#include <cmath>
#include <cstdlib>

namespace revkit::container::detail {

namespace {

class Parser {
 public:
  Parser(std::string_view t, std::uint32_t depth, std::uint64_t values) : t_(t), max_depth_(depth), max_values_(values) {}

  Json document() {
    Json v = value(0);
    ws();
    if (p_ != t_.size()) fail("trailing data");
    return v;
  }

 private:
  [[noreturn]] void fail(const std::string &why) const {
    throw Error("bad JSON at byte " + std::to_string(p_) + ": " + why);
  }
  void ws() {
    while (p_ < t_.size() && (t_[p_] == ' ' || t_[p_] == '\n' || t_[p_] == '\r' || t_[p_] == '\t')) ++p_;
  }
  bool eat(char c) {
    ws();
    if (p_ < t_.size() && t_[p_] == c) {
      ++p_;
      return true;
    }
    return false;
  }
  void expect(char c) {
    if (!eat(c)) fail(std::string("expected '") + c + "'");
  }
  bool word(std::string_view w) {
    if (t_.substr(p_, w.size()) != w) return false;
    p_ += w.size();
    return true;
  }

  Json value(std::uint32_t depth) {
    if (depth > max_depth_) throw LimitError("JSON nests deeper than " + std::to_string(max_depth_) + " levels");
    if (++values_ > max_values_) throw LimitError("JSON has more than " + std::to_string(max_values_) + " values");
    ws();
    if (p_ >= t_.size()) fail("unexpected end");
    Json v;
    const char c = t_[p_];
    if (c == '{') {
      ++p_;
      v.type = Json::Type::object;
      if (eat('}')) return v;
      do {
        ws();
        if (p_ >= t_.size() || t_[p_] != '"') fail("expected a key");
        std::string key = string();
        expect(':');
        v.fields.push_back(JsonField{std::move(key), value(depth + 1)});
      } while (eat(','));
      expect('}');
    } else if (c == '[') {
      ++p_;
      v.type = Json::Type::array;
      if (eat(']')) return v;
      do v.items.push_back(value(depth + 1));
      while (eat(','));
      expect(']');
    } else if (c == '"') {
      v.type = Json::Type::string;
      v.str = string();
    } else if (word("true")) {
      v.type = Json::Type::boolean;
      v.b = true;
    } else if (word("false")) {
      v.type = Json::Type::boolean;
    } else if (word("null")) {
    } else if (c == '-' || (c >= '0' && c <= '9')) {
      const std::size_t s = p_;
      if (t_[p_] == '-') ++p_;
      auto digits = [&] {
        const std::size_t d = p_;
        while (p_ < t_.size() && t_[p_] >= '0' && t_[p_] <= '9') ++p_;
        if (p_ == d) fail("bad number");
      };
      digits();
      if (p_ < t_.size() && t_[p_] == '.') {
        ++p_;
        digits();
      }
      if (p_ < t_.size() && (t_[p_] == 'e' || t_[p_] == 'E')) {
        ++p_;
        if (p_ < t_.size() && (t_[p_] == '+' || t_[p_] == '-')) ++p_;
        digits();
      }
      v.type = Json::Type::number;
      v.str = std::string(t_.substr(s, p_ - s));
      v.num = std::strtod(v.str.c_str(), nullptr);
    } else {
      fail("unexpected character");
    }
    return v;
  }

  static void utf8(std::string &out, std::uint32_t cp) {
    if (cp < 0x80) {
      out += static_cast<char>(cp);
    } else if (cp < 0x800) {
      out += static_cast<char>(0xc0 | cp >> 6);
      out += static_cast<char>(0x80 | (cp & 0x3f));
    } else if (cp < 0x10000) {
      out += static_cast<char>(0xe0 | cp >> 12);
      out += static_cast<char>(0x80 | ((cp >> 6) & 0x3f));
      out += static_cast<char>(0x80 | (cp & 0x3f));
    } else {
      out += static_cast<char>(0xf0 | cp >> 18);
      out += static_cast<char>(0x80 | ((cp >> 12) & 0x3f));
      out += static_cast<char>(0x80 | ((cp >> 6) & 0x3f));
      out += static_cast<char>(0x80 | (cp & 0x3f));
    }
  }

  std::uint32_t hex4() {
    if (p_ + 4 > t_.size()) fail("short \\u escape");
    std::uint32_t v = 0;
    for (int i = 0; i < 4; ++i) {
      const char c = t_[p_++];
      v <<= 4;
      if (c >= '0' && c <= '9') v |= static_cast<std::uint32_t>(c - '0');
      else if (c >= 'a' && c <= 'f') v |= static_cast<std::uint32_t>(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F') v |= static_cast<std::uint32_t>(c - 'A' + 10);
      else fail("bad \\u escape");
    }
    return v;
  }

  std::string string() {
    ++p_;  // the quote
    std::string out;
    for (;;) {
      if (p_ >= t_.size()) fail("unterminated string");
      const char c = t_[p_++];
      if (c == '"') return out;
      if (static_cast<unsigned char>(c) < 0x20) fail("control character in a string");
      if (c != '\\') {
        out += c;
        continue;
      }
      if (p_ >= t_.size()) fail("unterminated string");
      const char e = t_[p_++];
      switch (e) {
        case '"': out += '"'; break;
        case '\\': out += '\\'; break;
        case '/': out += '/'; break;
        case 'b': out += '\b'; break;
        case 'f': out += '\f'; break;
        case 'n': out += '\n'; break;
        case 'r': out += '\r'; break;
        case 't': out += '\t'; break;
        case 'u': {
          std::uint32_t cp = hex4();
          if (cp >= 0xd800 && cp < 0xdc00 && t_.substr(p_, 2) == "\\u") {
            const std::size_t save = p_;
            p_ += 2;
            const std::uint32_t lo = hex4();
            if (lo >= 0xdc00 && lo < 0xe000) cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
            else p_ = save, cp = 0xfffd;
          } else if (cp >= 0xd800 && cp < 0xe000) {
            cp = 0xfffd;
          }
          utf8(out, cp);
          break;
        }
        default: fail("bad escape");
      }
    }
  }

  std::string_view t_;
  std::size_t p_ = 0;
  std::uint32_t max_depth_;
  std::uint64_t max_values_;
  std::uint64_t values_ = 0;
};

}  // namespace

const Json *Json::get(std::string_view key) const {
  if (type != Type::object) return nullptr;
  for (auto it = fields.rbegin(); it != fields.rend(); ++it)
    if (it->first == key) return &it->second;
  return nullptr;
}

std::optional<std::uint64_t> Json::as_u64() const {
  if (type == Type::number) {
    if (!(num >= 0) || num >= 9.2e18 || std::floor(num) != num) return std::nullopt;
    return static_cast<std::uint64_t>(num);
  }
  if (type == Type::string) {
    if (str.empty() || str.size() > 18) return std::nullopt;
    std::uint64_t v = 0;
    for (char c : str) {
      if (c < '0' || c > '9') return std::nullopt;
      v = v * 10 + static_cast<std::uint64_t>(c - '0');
    }
    return v;
  }
  return std::nullopt;
}

Json parse_json(std::string_view text, std::uint32_t max_depth, std::uint64_t max_values) {
  return Parser(text, max_depth, max_values).document();
}

}  // namespace revkit::container::detail
