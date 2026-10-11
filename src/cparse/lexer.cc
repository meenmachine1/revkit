// The lexer and the shared Context (diagnostics, budget).

#include "token.h"

#include <algorithm>
#include <array>

namespace revkit::cparse::detail {

Context::Context(const Options &o, Result &r)
    : options(o), result(r), deadline_(std::chrono::steady_clock::now() + o.limits.wall_time) {}

void Context::diag(Severity s, std::uint32_t file, std::uint32_t line, std::uint32_t col, std::string text) {
  if (s == Severity::Error) ++result.errors;
  if (s == Severity::Warning) ++result.warnings;
  if (result.diagnostics.size() >= options.limits.max_diagnostics) {
    ++result.suppressed_diagnostics;
    return;
  }
  Diagnostic d;
  d.file = file < files.size() ? files[file].name : std::string();
  d.line = line;
  d.col = col;
  d.severity = s;
  d.text = std::move(text);
  result.diagnostics.push_back(std::move(d));
}

void Context::add_bytes(std::size_t n) {
  bytes_ += n;
  if (bytes_ > options.limits.max_bytes)
    throw LimitReached{"the sources exceed " + std::to_string(options.limits.max_bytes) + " bytes"};
}

void Context::add_expansion(std::size_t n) {
  expansion_ += n;
  if (expansion_ > options.limits.max_expansion_tokens)
    throw LimitReached{"macro expansion produced more than " + std::to_string(options.limits.max_expansion_tokens) +
                       " tokens"};
  if ((expansion_ & 0xfff) < n) check_time();
}

void Context::add_token() {
  if (++tokens_ > options.limits.max_tokens)
    throw LimitReached{"more than " + std::to_string(options.limits.max_tokens) + " tokens"};
  if ((tokens_ & 0xfff) == 0) check_time();
}

void Context::check_time() {
  if (std::chrono::steady_clock::now() > deadline_)
    throw LimitReached{"the parse took longer than " + std::to_string(options.limits.wall_time.count()) + " ms"};
}

void Context::check_nesting(std::uint32_t depth) {
  if (depth > options.limits.max_nesting)
    throw LimitReached{"nesting deeper than " + std::to_string(options.limits.max_nesting)};
}

Location Context::location(std::uint32_t file, std::uint32_t line) const {
  Location l;
  if (file < files.size()) {
    l.file = files[file].name;
    l.system = files[file].system || files[file].builtin;
  }
  l.line = line;
  return l;
}

bool is_ident_start(unsigned char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '$' || c >= 0x80;
}
bool is_ident_char(unsigned char c) { return is_ident_start(c) || (c >= '0' && c <= '9'); }

namespace {

bool is_digit(char c) { return c >= '0' && c <= '9'; }

// Longest punctuators first.
constexpr std::array<std::string_view, 25> kPuncts = {
    "<<=", ">>=", "...", "->*", "::", "->", "++", "--", "<<", ">>", "<=", ">=", "==",
    "!=",  "&&",  "||",  "*=",  "/=", "%=", "+=", "-=", "&=", "^=", "|=", "##",
};

// Removes line splices and turns \r\n and \r into \n. A spliced line's
// newlines are put back after it, so later lines keep their numbers.
std::string canonical(std::string_view in) {
  std::string out;
  out.reserve(in.size() + 1);
  std::size_t pending = 0;
  for (std::size_t i = 0; i < in.size(); ++i) {
    char c = in[i];
    if (c == '\r') {
      c = '\n';
      if (i + 1 < in.size() && in[i + 1] == '\n') ++i;
    }
    if (c == '\\') {
      std::size_t j = i + 1;
      while (j < in.size() && (in[j] == ' ' || in[j] == '\t')) ++j;  // a common mistake compilers accept
      if (j < in.size() && (in[j] == '\n' || in[j] == '\r')) {
        if (in[j] == '\r' && j + 1 < in.size() && in[j + 1] == '\n') ++j;
        i = j;
        ++pending;
        continue;
      }
    }
    out.push_back(c);
    if (c == '\n') {
      out.append(pending, '\n');
      pending = 0;
    }
  }
  out.append(pending, '\n');
  if (out.empty() || out.back() != '\n') out.push_back('\n');
  return out;
}

}  // namespace

std::vector<Token> tokenize(Context &ctx, std::uint32_t file, std::string_view input) {
  const std::string text = canonical(input);
  std::vector<Token> out;
  out.reserve(text.size() / 4);
  std::uint32_t line = 1;
  std::size_t line_start = 0;
  bool bol = true, space = false;
  // 0: nothing; 1: '#' started a line; 2: then include/include_next/import.
  int include_state = 0;
  const std::size_t n = text.size();
  auto col = [&](std::size_t p) { return static_cast<std::uint32_t>(p - line_start + 1); };
  std::size_t i = 0;
  auto push = [&](TK kind, std::size_t start, std::size_t end) {
    Token t;
    t.kind = kind;
    t.bol = bol;
    t.space = space;
    t.file = file;
    t.line = line;
    t.col = col(start);
    t.text.assign(text, start, end - start);
    out.push_back(std::move(t));
    if (include_state == 1) include_state = (kind == TK::Ident && (out.back().text == "include" ||
                                                                   out.back().text == "include_next" ||
                                                                   out.back().text == "import"))
                                                ? 2
                                                : 0;
    else if (bol && kind == TK::Punct && out.back().text == "#") include_state = 1;
    else include_state = 0;
    bol = false;
    space = false;
  };
  // Skips a quoted literal starting at the quote at `p`; returns the end.
  auto quoted = [&](std::size_t p, char q) {
    std::size_t j = p + 1;
    while (j < n && text[j] != q && text[j] != '\n') j += text[j] == '\\' && j + 1 < n && text[j + 1] != '\n' ? 2 : 1;
    if (j >= n || text[j] != q) {
      ctx.diag(Severity::Warning, file, line, col(p), std::string("missing terminating ") + q + " character");
      return j;
    }
    return j + 1;
  };
  while (i < n) {
    const char c = text[i];
    if (c == '\n') {
      ++line;
      line_start = ++i;
      bol = true;
      space = false;
      include_state = 0;
      continue;
    }
    if (c == ' ' || c == '\t' || c == '\f' || c == '\v') {
      space = true;
      ++i;
      continue;
    }
    if (c == '/' && i + 1 < n && text[i + 1] == '/') {
      while (i < n && text[i] != '\n') ++i;
      space = true;
      continue;
    }
    if (c == '/' && i + 1 < n && text[i + 1] == '*') {
      const std::uint32_t l0 = line, c0 = col(i);
      i += 2;
      while (i < n && !(text[i] == '*' && i + 1 < n && text[i + 1] == '/')) {
        if (text[i] == '\n') {
          ++line;
          line_start = i + 1;
        }
        ++i;
      }
      if (i >= n) {
        ctx.diag(Severity::Error, file, l0, c0, "unterminated comment");
        break;
      }
      i += 2;
      space = true;
      continue;
    }
    if (include_state == 2 && c == '<') {
      std::size_t j = i + 1;
      while (j < n && text[j] != '>' && text[j] != '\n') ++j;
      if (j < n && text[j] == '>') {
        push(TK::String, i, j + 1);
        i = j + 1;
        continue;
      }
    }
    // Numbers: a digit, or '.' and a digit, then pp-number characters.
    if (is_digit(c) || (c == '.' && i + 1 < n && is_digit(text[i + 1]))) {
      std::size_t j = i + 1;
      while (j < n) {
        char d = text[j];
        if ((d == '+' || d == '-') && (text[j - 1] == 'e' || text[j - 1] == 'E' || text[j - 1] == 'p' ||
                                       text[j - 1] == 'P'))
          ++j;
        else if (is_ident_char(static_cast<unsigned char>(d)) || d == '.')
          ++j;
        else if (d == '\'' && j + 1 < n && is_ident_char(static_cast<unsigned char>(text[j + 1])))
          j += 2;  // C23/C++14 digit separators
        else
          break;
      }
      push(TK::Number, i, j);
      i = j;
      continue;
    }
    // Character and string literals, with an encoding prefix.
    {
      std::size_t p = i;
      if (c == 'u' && i + 2 < n && text[i + 1] == '8' && (text[i + 2] == '"' || text[i + 2] == '\'')) p = i + 2;
      else if ((c == 'L' || c == 'u' || c == 'U') && i + 1 < n && (text[i + 1] == '"' || text[i + 1] == '\'')) p = i + 1;
      else if (c == '"' || c == '\'') p = i;
      else p = std::string_view::npos;
      // C++ raw strings: R"delim( ... )delim", with any prefix.
      std::size_t r = std::string_view::npos;
      if (c == 'R' && i + 1 < n && text[i + 1] == '"') r = i + 1;
      else if ((c == 'L' || c == 'u' || c == 'U') && i + 2 < n && text[i + 1] == 'R' && text[i + 2] == '"') r = i + 2;
      else if (c == 'u' && i + 3 < n && text[i + 1] == '8' && text[i + 2] == 'R' && text[i + 3] == '"') r = i + 3;
      if (r != std::string_view::npos) {
        std::size_t open = text.find('(', r);
        if (open != std::string::npos && open - r <= 17) {
          std::string close = ")" + text.substr(r + 1, open - r - 1) + "\"";
          std::size_t end = text.find(close, open);
          if (end != std::string::npos) {
            for (std::size_t k = i; k < end; ++k)
              if (text[k] == '\n') ++line;
            push(TK::String, i, end + close.size());
            i = end + close.size();
            continue;
          }
        }
      }
      if (p != std::string_view::npos) {
        std::size_t end = quoted(p, text[p]);
        push(text[p] == '"' ? TK::String : TK::Char, i, end);
        i = end;
        continue;
      }
    }
    if (is_ident_start(static_cast<unsigned char>(c))) {
      std::size_t j = i + 1;
      while (j < n && is_ident_char(static_cast<unsigned char>(text[j]))) ++j;
      push(TK::Ident, i, j);
      i = j;
      continue;
    }
    std::string_view rest(text.data() + i, n - i);
    bool matched = false;
    for (std::string_view p : kPuncts)
      if (rest.starts_with(p)) {
        push(TK::Punct, i, i + p.size());
        i += p.size();
        matched = true;
        break;
      }
    if (matched) continue;
    if (std::string_view("+-*/%&|^~!=<>?:;,.()[]{}#").find(c) != std::string_view::npos) {
      push(TK::Punct, i, i + 1);
      ++i;
      continue;
    }
    push(TK::Other, i, i + 1);
    ++i;
  }
  return out;
}

}  // namespace revkit::cparse::detail
