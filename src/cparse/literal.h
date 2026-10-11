// Literals and #if arithmetic (internal).
#pragma once

#include "token.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::cparse::detail {

struct IntLiteral {
  bool ok = false;
  bool is_float = false;  // a floating constant (not an integer one)
  std::uint64_t value = 0;
  bool is_unsigned = false;  // a u suffix, or a value only an unsigned type holds
  int longs = 0;             // l: 1, ll: 2
  bool overflow = false;
};
IntLiteral parse_int_literal(std::string_view text);

// The value of a character constant ('a', '\n', L'x', 'ab'), as GCC gives it.
bool char_value(std::string_view text, std::int64_t &out);

// The bytes a string literal denotes (escapes resolved, prefix and quotes
// dropped), and the reverse for __FILE__.
std::string string_value(std::string_view literal);
std::string quote_string(std::string_view s);

struct ExprResult {
  bool ok = false;
  std::int64_t value = 0;
  bool is_unsigned = false;
  std::string error;
};

// An #if expression over fully expanded tokens: identifiers left are 0
// (true and false are 1 and 0 in C++); intmax_t / uintmax_t arithmetic.
ExprResult evaluate_pp(const std::vector<Token> &toks, bool cplusplus, std::uint32_t max_depth);

}  // namespace revkit::cparse::detail
