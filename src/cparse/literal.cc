#include "literal.h"

#include <cctype>
#include <cstdint>

namespace revkit::cparse::detail {

IntLiteral parse_int_literal(std::string_view text) {
  IntLiteral r;
  std::string s;
  for (char c : text)
    if (c != '\'') s += c;
  if (s.empty()) return r;
  std::size_t i = 0;
  unsigned base = 10;
  if (s.size() > 1 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
    base = 16;
    i = 2;
  } else if (s.size() > 1 && s[0] == '0' && (s[1] == 'b' || s[1] == 'B')) {
    base = 2;
    i = 2;
  } else if (s[0] == '0') {
    base = 8;
  }
  const std::size_t digits_start = i;
  std::uint64_t v = 0;
  for (; i < s.size(); ++i) {
    char c = s[i];
    unsigned d;
    if (c >= '0' && c <= '9') d = unsigned(c - '0');
    else if (c >= 'a' && c <= 'f') d = unsigned(c - 'a' + 10);
    else if (c >= 'A' && c <= 'F') d = unsigned(c - 'A' + 10);
    else break;
    if (d >= base) {
      if (base == 8 && d < 10) {  // 09 is a floating constant's start (09.5), or an error
        base = 10;
      } else {
        break;
      }
    }
    if (v > (~std::uint64_t(0) - d) / base) r.overflow = true;
    v = v * base + d;
  }
  if (i == digits_start && base != 8) return r;
  // A floating constant: '.', an exponent, or a float suffix.
  if (i < s.size() && (s[i] == '.' || ((s[i] == 'e' || s[i] == 'E') && base == 10) ||
                       ((s[i] == 'p' || s[i] == 'P') && base == 16))) {
    r.is_float = true;
    r.ok = true;
    return r;
  }
  std::string_view suf(s.data() + i, s.size() - i);
  bool u = false;
  int l = 0;
  while (!suf.empty()) {
    char c = suf[0];
    if ((c == 'u' || c == 'U') && !u) {
      u = true;
      suf.remove_prefix(1);
    } else if ((suf.starts_with("ll") || suf.starts_with("LL")) && l == 0) {
      l = 2;
      suf.remove_prefix(2);
    } else if ((c == 'l' || c == 'L') && l == 0) {
      l = 1;
      suf.remove_prefix(1);
    } else if (suf.starts_with("i64") || suf.starts_with("I64")) {
      l = 2;
      suf.remove_prefix(3);
    } else if (suf.starts_with("i32") || suf.starts_with("i16") || suf.starts_with("i8")) {
      suf.remove_prefix(suf[1] == '8' ? 2 : 3);
    } else if ((c == 'z' || c == 'Z') && l == 0) {  // C++23 size_t
      l = 1;
      suf.remove_prefix(1);
    } else if ((c == 'f' || c == 'F') && base == 10) {
      r.is_float = true;
      r.ok = true;
      return r;
    } else {
      return r;
    }
  }
  r.ok = true;
  r.value = v;
  r.longs = l;
  // A decimal constant that doesn't fit long long is unsigned in practice
  // (GCC warns); octal and hex constants become unsigned by the rules.
  r.is_unsigned = u || v > 0x7fffffffffffffffULL;
  return r;
}

namespace {

// One character (with escapes) at text[i]; advances i.
std::uint32_t one_char(std::string_view text, std::size_t &i) {
  unsigned char c = static_cast<unsigned char>(text[i++]);
  if (c != '\\' || i >= text.size()) {
    // UTF-8: the code point.
    if (c >= 0xc0) {
      int n = c >= 0xf0 ? 3 : c >= 0xe0 ? 2 : 1;
      std::uint32_t cp = c & (0x3f >> n);
      for (int k = 0; k < n && i < text.size(); ++k) cp = (cp << 6) | (static_cast<unsigned char>(text[i++]) & 0x3f);
      return cp;
    }
    return c;
  }
  char e = text[i++];
  switch (e) {
    case 'n': return '\n';
    case 't': return '\t';
    case 'r': return '\r';
    case 'a': return '\a';
    case 'b': return '\b';
    case 'f': return '\f';
    case 'v': return '\v';
    case 'e':
    case 'E': return 27;
    case 'x': {
      std::uint32_t v = 0;
      while (i < text.size() && std::isxdigit(static_cast<unsigned char>(text[i]))) {
        char h = text[i++];
        v = (v << 4) | std::uint32_t(h <= '9' ? h - '0' : (h | 0x20) - 'a' + 10);
      }
      return v;
    }
    case 'u':
    case 'U': {
      std::uint32_t v = 0;
      for (int k = 0; k < (e == 'u' ? 4 : 8) && i < text.size() && std::isxdigit(static_cast<unsigned char>(text[i])); ++k) {
        char h = text[i++];
        v = (v << 4) | std::uint32_t(h <= '9' ? h - '0' : (h | 0x20) - 'a' + 10);
      }
      return v;
    }
    default:
      if (e >= '0' && e <= '7') {
        std::uint32_t v = std::uint32_t(e - '0');
        for (int k = 0; k < 2 && i < text.size() && text[i] >= '0' && text[i] <= '7'; ++k)
          v = v * 8 + std::uint32_t(text[i++] - '0');
        return v;
      }
      return static_cast<unsigned char>(e);
  }
}

}  // namespace

bool char_value(std::string_view text, std::int64_t &out) {
  std::size_t q = text.find('\'');
  if (q == std::string_view::npos || text.size() < q + 2 || text.back() != '\'') return false;
  const bool wide = q > 0;  // L, u, U, u8
  std::string_view body = text.substr(q + 1, text.size() - q - 2);
  if (body.empty()) return false;
  std::size_t i = 0;
  std::int64_t v = 0;
  int n = 0;
  while (i < body.size()) {
    std::uint32_t c = one_char(body, i);
    v = wide ? std::int64_t(c) : ((v << 8) | (c & 0xff));
    ++n;
  }
  // A plain one-character constant is a char converted to int: GCC's
  // chars are signed on x86 (this is where it differs, rarely mattering).
  if (!wide && n == 1 && v > 127) v -= 256;
  if (!wide && n > 1) v = std::int64_t(std::int32_t(std::uint32_t(v)));
  out = v;
  return true;
}

std::string string_value(std::string_view lit) {
  std::size_t q = lit.find('"');
  if (q == std::string_view::npos || lit.size() < q + 2) return {};
  std::string_view body = lit.substr(q + 1, lit.size() - q - 2);
  if (q > 0 && lit[q - 1] == 'R') {  // raw string
    std::size_t open = body.find('(');
    std::size_t close = body.rfind(')');
    if (open == std::string_view::npos || close == std::string_view::npos || close < open) return {};
    return std::string(body.substr(open + 1, close - open - 1));
  }
  std::string out;
  std::size_t i = 0;
  while (i < body.size()) {
    if (body[i] != '\\') {
      out += body[i++];
      continue;
    }
    std::uint32_t c = one_char(body, i);
    if (c < 0x80) {
      out += char(c);
    } else if (c < 0x800) {
      out += char(0xc0 | (c >> 6));
      out += char(0x80 | (c & 0x3f));
    } else if (c < 0x10000) {
      out += char(0xe0 | (c >> 12));
      out += char(0x80 | ((c >> 6) & 0x3f));
      out += char(0x80 | (c & 0x3f));
    } else {
      out += char(0xf0 | ((c >> 18) & 7));
      out += char(0x80 | ((c >> 12) & 0x3f));
      out += char(0x80 | ((c >> 6) & 0x3f));
      out += char(0x80 | (c & 0x3f));
    }
  }
  return out;
}

std::string quote_string(std::string_view s) {
  std::string out = "\"";
  for (char c : s) {
    if (c == '"' || c == '\\') out += '\\';
    out += c;
  }
  return out + "\"";
}

namespace {

struct PPEval {
  const std::vector<Token> &t;
  bool cpp;
  std::uint32_t max_depth;
  std::size_t i = 0;
  std::string error;
  std::uint32_t depth = 0;

  struct V {
    std::uint64_t v = 0;
    bool u = false;
  };

  bool at(std::string_view p) const { return i < t.size() && t[i].punct(p); }
  bool fail(std::string e) {
    if (error.empty()) error = std::move(e);
    return false;
  }

  bool primary(V &out) {
    if (++depth > max_depth) return fail("#if expression nested too deeply");
    struct D {
      std::uint32_t &d;
      ~D() { --d; }
    } dd{depth};
    if (i >= t.size()) return fail("#if expression ends early");
    const Token &k = t[i];
    if (k.punct("(")) {
      ++i;
      if (!expr(out)) return false;
      if (!at(")")) return fail("missing ')' in #if expression");
      ++i;
      return true;
    }
    if (k.punct("-") || k.punct("+") || k.punct("~") || k.punct("!")) {
      ++i;
      V x;
      if (!primary(x)) return false;
      if (k.text == "-") x.v = ~x.v + 1;
      else if (k.text == "~") x.v = ~x.v;
      else if (k.text == "!") {
        x.v = x.v == 0;
        x.u = false;
      }
      out = x;
      return true;
    }
    if (k.kind == TK::Number) {
      IntLiteral l = parse_int_literal(k.text);
      if (!l.ok || l.is_float) return fail("invalid integer constant '" + k.text + "' in #if");
      out = {l.value, l.is_unsigned};
      ++i;
      return true;
    }
    if (k.kind == TK::Char) {
      std::int64_t v;
      if (!char_value(k.text, v)) return fail("invalid character constant in #if");
      out = {std::uint64_t(v), false};
      ++i;
      return true;
    }
    if (k.kind == TK::Ident) {
      out = {cpp && k.text == "true" ? 1u : 0u, false};
      ++i;
      return true;
    }
    return fail("token '" + k.text + "' is not valid in #if expressions");
  }

  static int prec(const Token &k) {
    if (k.kind != TK::Punct) return -1;
    const std::string &s = k.text;
    if (s == "*" || s == "/" || s == "%") return 10;
    if (s == "+" || s == "-") return 9;
    if (s == "<<" || s == ">>") return 8;
    if (s == "<" || s == ">" || s == "<=" || s == ">=") return 7;
    if (s == "==" || s == "!=") return 6;
    if (s == "&") return 5;
    if (s == "^") return 4;
    if (s == "|") return 3;
    if (s == "&&") return 2;
    if (s == "||") return 1;
    return -1;
  }

  bool binary(V &lhs, int min) {
    for (;;) {
      if (i >= t.size()) return true;
      const Token &op = t[i];
      int p = prec(op);
      if (p < min) return true;
      ++i;
      V rhs;
      // && and || evaluate both sides here (no side effects), but division
      // by zero on the unevaluated side must not fail.
      if (!primary(rhs)) return false;
      while (i < t.size() && prec(t[i]) > p)
        if (!binary(rhs, prec(t[i]))) return false;
      const bool u = lhs.u || rhs.u;
      const std::string &s = op.text;
      auto sl = std::int64_t(lhs.v), sr = std::int64_t(rhs.v);
      V r{0, u};
      if (s == "*") r.v = lhs.v * rhs.v;
      else if (s == "/" || s == "%") {
        if (rhs.v == 0) {
          r.v = 0;  // GCC errors only if evaluated; treat as 0
        } else if (u) {
          r.v = s == "/" ? lhs.v / rhs.v : lhs.v % rhs.v;
        } else if (sl == INT64_MIN && sr == -1) {
          r.v = s == "/" ? lhs.v : 0;
        } else {
          r.v = std::uint64_t(s == "/" ? sl / sr : sl % sr);
        }
      } else if (s == "+") r.v = lhs.v + rhs.v;
      else if (s == "-") r.v = lhs.v - rhs.v;
      else if (s == "<<") {
        r.u = lhs.u;
        r.v = rhs.v >= 64 ? 0 : lhs.v << rhs.v;
      } else if (s == ">>") {
        r.u = lhs.u;
        r.v = rhs.v >= 64 ? (lhs.u || sl >= 0 ? 0 : ~std::uint64_t(0))
                          : (lhs.u ? lhs.v >> rhs.v : std::uint64_t(sl >> rhs.v));
      } else if (s == "<" || s == ">" || s == "<=" || s == ">=" || s == "==" || s == "!=") {
        bool b;
        if (s == "==") b = lhs.v == rhs.v;
        else if (s == "!=") b = lhs.v != rhs.v;
        else if (u) b = s == "<" ? lhs.v < rhs.v : s == ">" ? lhs.v > rhs.v : s == "<=" ? lhs.v <= rhs.v : lhs.v >= rhs.v;
        else b = s == "<" ? sl < sr : s == ">" ? sl > sr : s == "<=" ? sl <= sr : sl >= sr;
        r = {b ? 1u : 0u, false};
      } else if (s == "&") r.v = lhs.v & rhs.v;
      else if (s == "^") r.v = lhs.v ^ rhs.v;
      else if (s == "|") r.v = lhs.v | rhs.v;
      else if (s == "&&") r = {lhs.v && rhs.v ? 1u : 0u, false};
      else if (s == "||") r = {lhs.v || rhs.v ? 1u : 0u, false};
      lhs = r;
    }
  }

  bool conditional(V &out) {
    if (!primary(out) || !binary(out, 1)) return false;
    if (at("?")) {
      ++i;
      V a, b;
      if (!expr(a)) return false;
      if (!at(":")) return fail("missing ':' in #if expression");
      ++i;
      if (!conditional(b)) return false;
      V r = out.v ? a : b;
      r.u = a.u || b.u;
      out = r;
    }
    return true;
  }

  bool expr(V &out) {
    if (!conditional(out)) return false;
    while (at(",")) {
      ++i;
      if (!conditional(out)) return false;
    }
    return true;
  }
};

}  // namespace

ExprResult evaluate_pp(const std::vector<Token> &toks, bool cplusplus, std::uint32_t max_depth) {
  ExprResult r;
  if (toks.empty()) {
    r.error = "#if with no expression";
    return r;
  }
  PPEval e{toks, cplusplus, max_depth, 0, {}, 0};
  PPEval::V v;
  if (!e.expr(v)) {
    r.error = e.error;
    return r;
  }
  if (e.i != toks.size()) {
    r.error = "missing binary operator before token '" + toks[e.i].text + "'";
    return r;
  }
  r.ok = true;
  r.value = std::int64_t(v.v);
  r.is_unsigned = v.u;
  return r;
}

}  // namespace revkit::cparse::detail
