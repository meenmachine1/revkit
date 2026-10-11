#include "revkit/emu/json.hh"

#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <sstream>

namespace revkit::emu::json {

Value Value::boolean(bool b) {
  Value v;
  v.type_ = Type::boolean;
  v.b_ = b;
  return v;
}

Value Value::integer(std::int64_t i) {
  Value v;
  v.type_ = Type::integer;
  v.neg_ = i < 0;
  v.u_ = static_cast<std::uint64_t>(i);
  return v;
}

Value Value::unsigned_integer(std::uint64_t u) {
  Value v;
  v.type_ = Type::integer;
  v.u_ = u;
  return v;
}

Value Value::number(double d) {
  Value v;
  v.type_ = Type::number;
  v.d_ = d;
  return v;
}

Value Value::string(std::string s) {
  Value v;
  v.type_ = Type::string;
  v.s_ = std::move(s);
  return v;
}

Value Value::array() {
  Value v;
  v.type_ = Type::array;
  return v;
}

Value Value::object() {
  Value v;
  v.type_ = Type::object;
  return v;
}

const Value *Value::find(std::string_view key) const {
  for (const Member &m : members_)
    if (m.first == key) return &m.second;
  return nullptr;
}

Value &Value::set(std::string key, Value v) {
  type_ = Type::object;
  for (Member &m : members_)
    if (m.first == key) return m.second = std::move(v);
  members_.emplace_back(std::move(key), std::move(v));
  return members_.back().second;
}

Value &Value::push(Value v) {
  type_ = Type::array;
  items_.push_back(std::move(v));
  return items_.back();
}

std::string where(const Value &v) { return std::to_string(v.line) + ":" + std::to_string(v.column); }

std::string quote(std::string_view s) {
  std::string out = "\"";
  for (unsigned char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof buf, "\\u%04x", c);
          out += buf;
        } else {
          out.push_back(static_cast<char>(c));
        }
    }
  }
  return out + "\"";
}

namespace {

class Parser {
 public:
  explicit Parser(std::string_view in) : in_(in) {}

  Value document() {
    Value v = value(0);
    ws();
    if (pos_ < in_.size()) fail("unexpected text after the document");
    return v;
  }

 private:
  [[noreturn]] void fail(const std::string &what) const {
    throw Error(std::to_string(line_) + ":" + std::to_string(col_) + ": " + what);
  }

  char peek() const { return pos_ < in_.size() ? in_[pos_] : '\0'; }
  char get() {
    char c = in_[pos_++];
    if (c == '\n') {
      ++line_;
      col_ = 1;
    } else {
      ++col_;
    }
    return c;
  }

  void ws() {
    while (pos_ < in_.size()) {
      const char c = peek();
      if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
        get();
      } else if (c == '/' && pos_ + 1 < in_.size() && in_[pos_ + 1] == '/') {
        while (pos_ < in_.size() && peek() != '\n') get();
      } else if (c == '/' && pos_ + 1 < in_.size() && in_[pos_ + 1] == '*') {
        get();
        get();
        while (pos_ + 1 < in_.size() && !(peek() == '*' && in_[pos_ + 1] == '/')) get();
        if (pos_ + 1 >= in_.size()) fail("unterminated comment");
        get();
        get();
      } else {
        break;
      }
    }
  }

  Value value(int depth) {
    if (depth > 64) fail("nesting is too deep");
    ws();
    const int line = line_, col = col_;
    if (pos_ >= in_.size()) fail("unexpected end of text");
    Value v;
    const char c = peek();
    if (c == '{') {
      get();
      v = Value::object();
      ws();
      if (peek() == '}') {
        get();
      } else {
        while (true) {
          ws();
          if (peek() != '"') fail("expected a quoted key");
          std::string key = string();
          if (v.find(key) != nullptr) fail("duplicate key \"" + key + "\"");
          ws();
          if (peek() != ':') fail("expected ':' after \"" + key + "\"");
          get();
          Value member = value(depth + 1);
          v.set(std::move(key), std::move(member));
          ws();
          if (peek() == ',') {
            get();
            ws();
            if (peek() == '}') {  // a trailing comma
              get();
              break;
            }
            continue;
          }
          if (peek() == '}') {
            get();
            break;
          }
          fail("expected ',' or '}'");
        }
      }
    } else if (c == '[') {
      get();
      v = Value::array();
      ws();
      if (peek() == ']') {
        get();
      } else {
        while (true) {
          v.push(value(depth + 1));
          ws();
          if (peek() == ',') {
            get();
            ws();
            if (peek() == ']') {
              get();
              break;
            }
            continue;
          }
          if (peek() == ']') {
            get();
            break;
          }
          fail("expected ',' or ']'");
        }
      }
    } else if (c == '"') {
      v = Value::string(string());
    } else if (in_.substr(pos_, 4) == "true") {
      for (int i = 0; i < 4; ++i) get();
      v = Value::boolean(true);
    } else if (in_.substr(pos_, 5) == "false") {
      for (int i = 0; i < 5; ++i) get();
      v = Value::boolean(false);
    } else if (in_.substr(pos_, 4) == "null") {
      for (int i = 0; i < 4; ++i) get();
    } else if (c == '-' || (c >= '0' && c <= '9')) {
      v = number();
    } else {
      fail(std::string("unexpected character '") + c + "'");
    }
    v.line = line;
    v.column = col;
    return v;
  }

  std::string string() {
    get();  // the quote
    std::string out;
    while (true) {
      if (pos_ >= in_.size()) fail("unterminated string");
      char c = get();
      if (c == '"') break;
      if (static_cast<unsigned char>(c) < 0x20) fail("control character in a string");
      if (c != '\\') {
        out.push_back(c);
        continue;
      }
      if (pos_ >= in_.size()) fail("unterminated string");
      c = get();
      switch (c) {
        case '"': out.push_back('"'); break;
        case '\\': out.push_back('\\'); break;
        case '/': out.push_back('/'); break;
        case 'b': out.push_back('\b'); break;
        case 'f': out.push_back('\f'); break;
        case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break;
        case 't': out.push_back('\t'); break;
        case 'u': {
          if (pos_ + 4 > in_.size()) fail("short \\u escape");
          unsigned cp = 0;
          for (int i = 0; i < 4; ++i) {
            const char h = get();
            cp <<= 4;
            if (h >= '0' && h <= '9') cp |= static_cast<unsigned>(h - '0');
            else if (h >= 'a' && h <= 'f') cp |= static_cast<unsigned>(h - 'a' + 10);
            else if (h >= 'A' && h <= 'F') cp |= static_cast<unsigned>(h - 'A' + 10);
            else fail("bad \\u escape");
          }
          if (cp < 0x80) {
            out.push_back(static_cast<char>(cp));
          } else if (cp < 0x800) {
            out.push_back(static_cast<char>(0xc0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
          } else {
            out.push_back(static_cast<char>(0xe0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
          }
          break;
        }
        default: fail(std::string("bad escape \\") + c);
      }
    }
    return out;
  }

  Value number() {
    const std::size_t start = pos_;
    bool neg = false;
    if (peek() == '-') {
      neg = true;
      get();
    }
    bool fraction = false;
    while (pos_ < in_.size()) {
      const char c = peek();
      if (c >= '0' && c <= '9') {
        get();
      } else if (c == '.' || c == 'e' || c == 'E' || ((c == '+' || c == '-') && fraction)) {
        fraction = true;
        get();
      } else {
        break;
      }
    }
    const std::string text(in_.substr(start, pos_ - start));
    if (text == "-" || text.empty()) fail("bad number");
    if (fraction) return Value::number(std::strtod(text.c_str(), nullptr));
    errno = 0;
    const std::uint64_t u = std::strtoull(text.c_str() + (neg ? 1 : 0), nullptr, 10);
    if (errno != 0) fail("number out of range: " + text);
    Value v = Value::unsigned_integer(neg ? ~u + 1 : u);
    if (neg && u != 0) v = Value::integer(-static_cast<std::int64_t>(u));
    return v;
  }

  std::string_view in_;
  std::size_t pos_ = 0;
  int line_ = 1, col_ = 1;
};

void dump_to(const Value &v, std::ostringstream &o, int indent, bool pretty) {
  auto pad = [&](int n) {
    if (pretty) o << '\n' << std::string(static_cast<std::size_t>(n), ' ');
  };
  switch (v.type()) {
    case Value::Type::null: o << "null"; return;
    case Value::Type::boolean: o << (v.as_bool() ? "true" : "false"); return;
    case Value::Type::integer:
      if (v.negative()) o << static_cast<std::int64_t>(v.as_u64());
      else o << v.as_u64();
      return;
    case Value::Type::number: {
      char buf[64];
      std::snprintf(buf, sizeof buf, "%.17g", v.as_double());
      o << buf;
      return;
    }
    case Value::Type::string: o << quote(v.as_string()); return;
    case Value::Type::array: {
      bool scalars = v.items().size() <= 8;
      for (const Value &x : v.items()) scalars = scalars && !x.is_array() && !x.is_object();
      if (v.items().empty()) {
        o << "[]";
        return;
      }
      o << '[';
      for (std::size_t i = 0; i < v.items().size(); ++i) {
        if (i) o << (scalars || !pretty ? ", " : ",");
        if (!scalars) pad(indent + 2);
        dump_to(v.items()[i], o, indent + 2, pretty);
      }
      if (!scalars) pad(indent);
      o << ']';
      return;
    }
    case Value::Type::object: {
      if (v.members().empty()) {
        o << "{}";
        return;
      }
      o << '{';
      for (std::size_t i = 0; i < v.members().size(); ++i) {
        if (i) o << ',';
        if (pretty) pad(indent + 2);
        else if (i) o << ' ';
        o << quote(v.members()[i].first) << ": ";
        dump_to(v.members()[i].second, o, indent + 2, pretty);
      }
      pad(indent);
      o << '}';
      return;
    }
  }
}

}  // namespace

Value Value::parse(std::string_view text) { return Parser(text).document(); }

std::string Value::dump(int indent) const {
  std::ostringstream o;
  dump_to(*this, o, indent, true);
  return o.str();
}

std::string Value::compact() const {
  std::ostringstream o;
  dump_to(*this, o, 0, false);
  return o.str();
}

}  // namespace revkit::emu::json
