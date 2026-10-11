#include "xml.hh"

#include <cctype>
#include <cstdlib>

namespace revkit::debug::xml {

std::vector<const Node *> Node::all(std::string_view n) const {
  std::vector<const Node *> out;
  for (const Node &c : children)
    if (c.name == n) out.push_back(&c);
  return out;
}

const Node *Node::first(std::string_view n) const {
  for (const Node &c : children)
    if (c.name == n) return &c;
  return nullptr;
}

std::optional<unsigned long long> number(std::string_view text) {
  std::string s(text);
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();
  std::size_t i = 0;
  while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
  s = s.substr(i);
  if (s.empty()) return std::nullopt;
  int base = 10;
  if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
    base = 16;
    s = s.substr(2);
  }
  char *end = nullptr;
  const unsigned long long v = std::strtoull(s.c_str(), &end, base);
  if (end == s.c_str() || *end != '\0') return std::nullopt;
  return v;
}

namespace {

class Parser {
 public:
  explicit Parser(std::string_view s) : s_(s) {}

  std::optional<Node> document(std::string *error) {
    try {
      skip_misc();
      if (!at('<')) fail("no root element");
      Node root = element();
      return root;
    } catch (const std::string &e) {
      if (error != nullptr) *error = e;
      return std::nullopt;
    }
  }

 private:
  [[noreturn]] void fail(const std::string &what) { throw what + " at offset " + std::to_string(i_); }
  bool at(char c) const { return i_ < s_.size() && s_[i_] == c; }
  bool starts(std::string_view p) const { return s_.substr(i_, p.size()) == p; }
  void ws() {
    while (i_ < s_.size() && std::isspace(static_cast<unsigned char>(s_[i_]))) ++i_;
  }
  void skip_until(std::string_view end) {
    const auto p = s_.find(end, i_);
    if (p == std::string_view::npos) fail("unterminated markup");
    i_ = p + end.size();
  }
  // Prolog, comments, processing instructions, doctype.
  void skip_misc() {
    for (;;) {
      ws();
      if (starts("<?")) skip_until("?>");
      else if (starts("<!--")) skip_until("-->");
      else if (starts("<!DOCTYPE") || starts("<!doctype")) {
        // May hold an internal subset in brackets.
        int depth = 0;
        for (; i_ < s_.size(); ++i_) {
          if (s_[i_] == '[') ++depth;
          else if (s_[i_] == ']') --depth;
          else if (s_[i_] == '>' && depth <= 0) {
            ++i_;
            break;
          }
        }
      } else return;
    }
  }
  std::string name() {
    const std::size_t start = i_;
    while (i_ < s_.size()) {
      const char c = s_[i_];
      if (std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == ':' || c == '-' || c == '.') ++i_;
      else break;
    }
    if (i_ == start) fail("expected a name");
    return std::string(s_.substr(start, i_ - start));
  }
  std::string unescape(std::string_view t) {
    std::string out;
    for (std::size_t k = 0; k < t.size(); ++k) {
      if (t[k] != '&') {
        out += t[k];
        continue;
      }
      const auto semi = t.find(';', k);
      if (semi == std::string_view::npos) {
        out += t[k];
        continue;
      }
      const std::string_view ent = t.substr(k + 1, semi - k - 1);
      if (ent == "lt") out += '<';
      else if (ent == "gt") out += '>';
      else if (ent == "amp") out += '&';
      else if (ent == "quot") out += '"';
      else if (ent == "apos") out += '\'';
      else if (!ent.empty() && ent[0] == '#') {
        const unsigned long v = ent.size() > 1 && (ent[1] == 'x' || ent[1] == 'X')
                                    ? std::strtoul(std::string(ent.substr(2)).c_str(), nullptr, 16)
                                    : std::strtoul(std::string(ent.substr(1)).c_str(), nullptr, 10);
        if (v < 0x80) out += static_cast<char>(v);
        else if (v < 0x800) {
          out += static_cast<char>(0xc0 | (v >> 6));
          out += static_cast<char>(0x80 | (v & 0x3f));
        } else {
          out += static_cast<char>(0xe0 | ((v >> 12) & 0x0f));
          out += static_cast<char>(0x80 | ((v >> 6) & 0x3f));
          out += static_cast<char>(0x80 | (v & 0x3f));
        }
      } else {
        out += '&';
        out += ent;
        out += ';';
      }
      k = semi;
    }
    return out;
  }
  Node element() {
    if (++depth_ > 64) fail("elements nested too deeply");
    ++i_;  // '<'
    Node n;
    n.name = name();
    for (;;) {
      ws();
      if (at('/')) {
        ++i_;
        if (!at('>')) fail("expected '>'");
        ++i_;
        --depth_;
        return n;
      }
      if (at('>')) {
        ++i_;
        break;
      }
      std::string key = name();
      ws();
      if (!at('=')) fail("expected '=' after " + key);
      ++i_;
      ws();
      if (!at('"') && !at('\'')) fail("expected a quoted value for " + key);
      const char q = s_[i_++];
      const auto end = s_.find(q, i_);
      if (end == std::string_view::npos) fail("unterminated attribute " + key);
      n.attrs[key] = unescape(s_.substr(i_, end - i_));
      i_ = end + 1;
    }
    // Content.
    for (;;) {
      if (i_ >= s_.size()) fail("unterminated element " + n.name);
      if (starts("</")) {
        i_ += 2;
        const std::string close = name();
        if (close != n.name) fail("</" + close + "> closes <" + n.name + ">");
        ws();
        if (!at('>')) fail("expected '>'");
        ++i_;
        --depth_;
        return n;
      }
      if (starts("<!--")) {
        skip_until("-->");
        continue;
      }
      if (starts("<![CDATA[")) {
        i_ += 9;
        const auto end = s_.find("]]>", i_);
        if (end == std::string_view::npos) fail("unterminated CDATA");
        n.text += s_.substr(i_, end - i_);
        i_ = end + 3;
        continue;
      }
      if (starts("<?")) {
        skip_until("?>");
        continue;
      }
      if (at('<')) {
        n.children.push_back(element());
        continue;
      }
      const auto lt = s_.find('<', i_);
      const auto end = lt == std::string_view::npos ? s_.size() : lt;
      n.text += unescape(s_.substr(i_, end - i_));
      i_ = end;
    }
  }

  std::string_view s_;
  std::size_t i_ = 0;
  int depth_ = 0;
};

}  // namespace

std::optional<Node> parse(std::string_view text, std::string *error) { return Parser(text).document(error); }

}  // namespace revkit::debug::xml
