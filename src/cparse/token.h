// Tokens, the file table, diagnostics and the resource budget shared by
// the lexer, preprocessor and parser (internal).
#pragma once

#include "revkit/cparse/cparse.h"

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::cparse::detail {

enum class TK : std::uint8_t {
  Eof,
  Ident,
  Number,  // a preprocessing number
  Char,    // a character constant, with its prefix and quotes
  String,  // a string literal, with its prefix and quotes
  Punct,
  Other,   // a stray character
  Pragma,  // #pragma pack (and _Pragma, __pragma) handed to the parser: text is "pack", args in `extra`
};

struct Token {
  TK kind = TK::Eof;
  bool bol = false;    // first token of its line (directives start here)
  bool space = false;  // whitespace before it
  std::uint32_t file = 0;
  std::uint32_t line = 0;
  std::uint32_t col = 0;
  std::uint32_t hideset = 0;  // interned set of macros not to expand again (0: empty)
  std::string text;
  std::string extra;

  bool is(std::string_view s) const { return (kind == TK::Punct || kind == TK::Ident) && text == s; }
  bool punct(std::string_view s) const { return kind == TK::Punct && text == s; }
  bool ident(std::string_view s) const { return kind == TK::Ident && text == s; }
};

struct FileInfo {
  std::string name;      // as shown in diagnostics
  std::string canonical; // the resolved path ("" for inline sources and built-ins)
  bool system = false;
  bool builtin = false;
  int search_index = -1;  // the include directory it was found in, for #include_next
};

// Raised when a Limits bound is reached; ends the parse with what it has.
struct LimitReached {
  std::string what;
};

class Context {
 public:
  Context(const Options &options, Result &result);

  const Options &options;
  Result &result;
  std::vector<FileInfo> files;

  void diag(Severity s, std::uint32_t file, std::uint32_t line, std::uint32_t col, std::string text);
  void diag(Severity s, const Token &at, std::string text) { diag(s, at.file, at.line, at.col, std::move(text)); }
  void error(const Token &at, std::string text) { diag(Severity::Error, at, std::move(text)); }
  void warning(const Token &at, std::string text) { diag(Severity::Warning, at, std::move(text)); }

  // Budget checks: throw LimitReached.
  void add_bytes(std::size_t n);
  void add_expansion(std::size_t n);
  void add_token();
  void check_time();
  void check_nesting(std::uint32_t depth);

  Location location(std::uint32_t file, std::uint32_t line) const;

 private:
  std::chrono::steady_clock::time_point deadline_;
  std::size_t bytes_ = 0, expansion_ = 0, tokens_ = 0;
};

// Splits `text` into preprocessing tokens. Line splices are removed (the
// lines they joined still count), comments become whitespace, and every
// token knows whether it starts its line. After `#include` (and
// include_next, import) at the start of a line, a <...> header name is one
// String token whose text keeps its brackets.
std::vector<Token> tokenize(Context &ctx, std::uint32_t file, std::string_view text);

bool is_ident_start(unsigned char c);
bool is_ident_char(unsigned char c);

}  // namespace revkit::cparse::detail
