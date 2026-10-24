// A YAML subset for dsd's and ds-rom's config files (dsd.hh).
#include "revkit/nds/dsd.hh"

#include <charconv>

namespace revkit::nds {

namespace {

constexpr std::size_t kMaxDepth = 64;
constexpr std::size_t kMaxLines = 1u << 20;

struct Line {
  std::size_t indent = 0;
  std::string text;  // without indentation, comment and trailing space
  std::size_t number = 0;
};

// Removes a `#` comment that isn't inside quotes (a `#` starts one at the
// line's start or after whitespace).
std::string StripComment(std::string_view s) {
  char quote = 0;
  for (std::size_t i = 0; i < s.size(); ++i) {
    const char c = s[i];
    if (quote) {
      if (c == quote) {
        if (quote == '\'' && i + 1 < s.size() && s[i + 1] == '\'') {
          ++i;
          continue;
        }
        quote = 0;
      } else if (quote == '"' && c == '\\') {
        ++i;
      }
      continue;
    }
    if (c == '"' || c == '\'') {
      // Quotes open a scalar only at its start.
      if (i == 0 || s[i - 1] == ' ' || s[i - 1] == ':' || s[i - 1] == '-' || s[i - 1] == '[' || s[i - 1] == ',')
        quote = c;
      continue;
    }
    if (c == '#' && (i == 0 || s[i - 1] == ' ' || s[i - 1] == '\t')) return std::string(s.substr(0, i));
  }
  return std::string(s);
}

std::string_view TrimRight(std::string_view s) {
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) s.remove_suffix(1);
  return s;
}

std::string_view Trim(std::string_view s) {
  s = TrimRight(s);
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
  return s;
}

class Parser {
 public:
  explicit Parser(std::vector<Line> lines) : lines_(std::move(lines)) {}

  std::optional<YamlNode> Document(std::string *error) {
    YamlNode root;
    root.kind = YamlNode::Kind::map;
    if (lines_.empty()) return root;
    if (!Block(lines_[0].indent, 0, root)) {
      if (error) *error = error_;
      return std::nullopt;
    }
    if (pos_ < lines_.size()) {
      if (error) *error = "line " + std::to_string(lines_[pos_].number) + ": unexpected indentation";
      return std::nullopt;
    }
    return root;
  }

 private:
  bool Fail(const std::string &m) {
    if (error_.empty()) error_ = "line " + std::to_string(pos_ < lines_.size() ? lines_[pos_].number : 0) + ": " + m;
    return false;
  }

  static bool IsItem(const std::string &t) { return t == "-" || t.starts_with("- "); }

  // The block (map or sequence) whose lines start at `indent`.
  bool Block(std::size_t indent, std::size_t depth, YamlNode &out) {
    if (depth > kMaxDepth) return Fail("nested too deeply");
    if (pos_ >= lines_.size()) return true;
    if (IsItem(lines_[pos_].text)) return Seq(indent, depth, out);
    return Map(indent, depth, out);
  }

  bool Seq(std::size_t indent, std::size_t depth, YamlNode &out) {
    out.kind = YamlNode::Kind::seq;
    while (pos_ < lines_.size() && lines_[pos_].indent == indent && IsItem(lines_[pos_].text)) {
      Line &l = lines_[pos_];
      std::string rest = l.text == "-" ? std::string() : l.text.substr(2);
      std::size_t lead = 0;
      while (lead < rest.size() && rest[lead] == ' ') ++lead;
      rest = rest.substr(lead);
      YamlNode item;
      if (rest.empty()) {
        ++pos_;
        if (pos_ < lines_.size() && lines_[pos_].indent > indent) {
          if (!Block(lines_[pos_].indent, depth + 1, item)) return false;
        }
      } else if (KeyOf(rest)) {
        // `- key: value` opens a map whose keys line up with `key`.
        l.indent = indent + 2 + lead;
        l.text = rest;
        if (!Map(l.indent, depth + 1, item)) return false;
      } else if (IsItem(rest)) {
        l.indent = indent + 2 + lead;
        l.text = rest;
        if (!Seq(l.indent, depth + 1, item)) return false;
      } else {
        if (!Scalar(rest, item)) return false;
        ++pos_;
      }
      out.seq.push_back(std::move(item));
    }
    return true;
  }

  // The key of a `key: value` or `key:` line, or nullopt.
  static std::optional<std::pair<std::string, std::string>> KeyOf(const std::string &t) {
    if (t.empty()) return std::nullopt;
    std::size_t i = 0;
    std::string key;
    if (t[0] == '"' || t[0] == '\'') {
      const char q = t[0];
      std::size_t j = 1;
      for (; j < t.size(); ++j) {
        if (t[j] == q) break;
        if (q == '"' && t[j] == '\\') ++j;
      }
      if (j >= t.size()) return std::nullopt;
      key = t.substr(1, j - 1);
      i = j + 1;
      if (i >= t.size() || t[i] != ':') return std::nullopt;
    } else {
      for (; i < t.size(); ++i) {
        if (t[i] == ':' && (i + 1 == t.size() || t[i + 1] == ' ')) break;
      }
      if (i >= t.size()) return std::nullopt;
      key = std::string(Trim(t.substr(0, i)));
      if (key.empty() || key[0] == '[' || key[0] == '{') return std::nullopt;
    }
    std::string value = std::string(Trim(std::string_view(t).substr(i + 1)));
    return std::make_pair(std::move(key), std::move(value));
  }

  bool Map(std::size_t indent, std::size_t depth, YamlNode &out) {
    out.kind = YamlNode::Kind::map;
    while (pos_ < lines_.size() && lines_[pos_].indent == indent) {
      const Line &l = lines_[pos_];
      if (IsItem(l.text)) return Fail("a sequence item where a key was expected");
      auto kv = KeyOf(l.text);
      if (!kv) return Fail("expected `key: value`");
      if (out.map.size() >= (1u << 16)) return Fail("too many keys");
      YamlNode value;
      ++pos_;
      if (kv->second.empty()) {
        if (pos_ < lines_.size() && lines_[pos_].indent > indent) {
          if (!Block(lines_[pos_].indent, depth + 1, value)) return false;
        } else if (pos_ < lines_.size() && lines_[pos_].indent == indent && IsItem(lines_[pos_].text)) {
          // A sequence may sit at its key's indentation.
          if (!Seq(indent, depth + 1, value)) return false;
        }
      } else {
        --pos_;
        if (!Scalar(kv->second, value)) return false;
        ++pos_;
        // A tag alone (`kind: !Unknown`) may be followed by its value's block.
        if (!value.tag.empty() && value.scalar.empty() && pos_ < lines_.size() && lines_[pos_].indent > indent) {
          std::string tag = value.tag;
          if (!Block(lines_[pos_].indent, depth + 1, value)) return false;
          value.tag = tag;
        }
      }
      out.map.push_back(YamlEntry{std::move(kv->first), std::move(value)});
    }
    if (pos_ < lines_.size() && lines_[pos_].indent > indent) return Fail("unexpected indentation");
    return true;
  }

  bool Scalar(std::string text, YamlNode &out) {
    out.kind = YamlNode::Kind::scalar;
    std::string_view t = Trim(text);
    if (!t.empty() && t[0] == '!') {
      std::size_t sp = t.find(' ');
      out.tag = std::string(t.substr(1, sp == std::string_view::npos ? std::string_view::npos : sp - 1));
      t = sp == std::string_view::npos ? std::string_view() : Trim(t.substr(sp + 1));
    }
    if (t == "[]") {
      out.kind = YamlNode::Kind::seq;
      return true;
    }
    if (t == "{}") {
      out.kind = YamlNode::Kind::map;
      return true;
    }
    if (!t.empty() && (t[0] == '[' || t[0] == '{')) return Fail("flow collections are not supported");
    if (!t.empty() && (t[0] == '&' || t[0] == '*')) return Fail("anchors and aliases are not supported");
    if (!t.empty() && (t[0] == '|' || t[0] == '>')) return Fail("block scalars are not supported");
    if (!t.empty() && t[0] == '\'') {
      std::string s;
      std::size_t i = 1;
      for (; i < t.size(); ++i) {
        if (t[i] == '\'') {
          if (i + 1 < t.size() && t[i + 1] == '\'') {
            s += '\'';
            ++i;
            continue;
          }
          break;
        }
        s += t[i];
      }
      if (i >= t.size()) return Fail("unterminated quoted scalar");
      out.scalar = std::move(s);
      return true;
    }
    if (!t.empty() && t[0] == '"') {
      std::string s;
      std::size_t i = 1;
      for (; i < t.size(); ++i) {
        char c = t[i];
        if (c == '"') break;
        if (c == '\\' && i + 1 < t.size()) {
          char e = t[++i];
          switch (e) {
            case 'n': s += '\n'; break;
            case 't': s += '\t'; break;
            case '0': s += '\0'; break;
            case '\\': s += '\\'; break;
            case '"': s += '"'; break;
            case '/': s += '/'; break;
            case 'x': {
              unsigned v = 0;
              if (i + 2 >= t.size() || std::from_chars(t.data() + i + 1, t.data() + i + 3, v, 16).ec != std::errc())
                return Fail("bad \\x escape");
              s += static_cast<char>(v);
              i += 2;
              break;
            }
            default: s += e; break;
          }
          continue;
        }
        s += c;
      }
      if (i >= t.size()) return Fail("unterminated quoted scalar");
      out.scalar = std::move(s);
      return true;
    }
    out.scalar = std::string(t);
    if (out.scalar == "~" || out.scalar == "null") out.scalar.clear();
    return true;
  }

  std::vector<Line> lines_;
  std::size_t pos_ = 0;
  std::string error_;
};

}  // namespace

const YamlNode *YamlNode::get(std::string_view key) const {
  if (kind != Kind::map) return nullptr;
  for (const auto &[k, v] : map)
    if (k == key) return &v;
  return nullptr;
}

std::string YamlNode::str(std::string_view key) const {
  const YamlNode *n = get(key);
  return n && n->kind == Kind::scalar ? n->scalar : std::string();
}

std::optional<std::uint64_t> YamlNode::num(std::string_view key) const {
  const YamlNode *n = get(key);
  if (!n || n->kind != Kind::scalar) return std::nullopt;
  return parse_number(n->scalar);
}

bool YamlNode::flag(std::string_view key) const {
  const std::string s = str(key);
  return s == "true" || s == "True" || s == "yes" || s == "1";
}

std::optional<std::uint64_t> parse_number(std::string_view s) {
  s = Trim(s);
  if (s.empty()) return std::nullopt;
  int base = 10;
  if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
    base = 16;
    s.remove_prefix(2);
  }
  std::uint64_t v = 0;
  // Underscores are allowed between digits, as Rust's literals have them.
  std::string digits;
  for (char c : s)
    if (c != '_') digits += c;
  if (digits.empty()) return std::nullopt;
  auto r = std::from_chars(digits.data(), digits.data() + digits.size(), v, base);
  if (r.ec != std::errc() || r.ptr != digits.data() + digits.size()) return std::nullopt;
  return v;
}

std::optional<YamlNode> parse_yaml(std::string_view text, std::string *error) {
  std::vector<Line> lines;
  std::size_t number = 0;
  std::size_t start = 0;
  while (start <= text.size()) {
    std::size_t end = text.find('\n', start);
    if (end == std::string_view::npos) end = text.size();
    std::string_view raw = text.substr(start, end - start);
    ++number;
    if (lines.size() >= kMaxLines) {
      if (error) *error = "too many lines";
      return std::nullopt;
    }
    if (number == 1 && raw.starts_with("\xEF\xBB\xBF")) raw.remove_prefix(3);
    std::string body = std::string(TrimRight(StripComment(raw)));
    std::size_t indent = 0;
    while (indent < body.size() && body[indent] == ' ') ++indent;
    if (indent < body.size() && body[indent] == '\t') {
      if (error) *error = "line " + std::to_string(number) + ": tab in indentation";
      return std::nullopt;
    }
    std::string content = body.substr(indent);
    if (!content.empty() && content != "---" && content != "...")
      lines.push_back({indent, std::move(content), number});
    if (end == text.size()) break;
    start = end + 1;
  }
  Parser p(std::move(lines));
  return p.Document(error);
}

}  // namespace revkit::nds
