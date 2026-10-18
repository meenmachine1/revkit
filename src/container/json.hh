// A small JSON reader for the packers' indexes (asar's header, pkg's and
// Deno's file lists), written for hostile input: bounded depth and size,
// strict syntax, every string kept as raw UTF-8 (escapes decoded, lone
// surrogates as U+FFFD). Internal.
#pragma once

#include "revkit/container/container.hh"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace revkit::container::detail {

struct JsonField;

struct Json {
  enum class Type : std::uint8_t { null, boolean, number, string, array, object };
  Type type = Type::null;
  bool b = false;
  double num = 0;
  std::string str;  // a string's value; a number's text as written
  std::vector<Json> items;                           // array
  std::vector<JsonField> fields;  // object, in order (a repeated key: the last wins in get())

  bool is_object() const { return type == Type::object; }
  bool is_array() const { return type == Type::array; }
  bool is_string() const { return type == Type::string; }
  bool is_number() const { return type == Type::number; }
  // A field of an object (the last of that name), or null.
  const Json *get(std::string_view key) const;
  // A non-negative integer from a number, or from a string of digits (asar
  // writes offsets as strings); nullopt otherwise or past 2^63.
  std::optional<std::uint64_t> as_u64() const;
};

// An object's member (first: the key, second: the value).
struct JsonField {
  std::string first;
  Json second;
};

// Parses a whole document. Error on bad syntax, nesting past max_depth or
// more than max_values values.
Json parse_json(std::string_view text, std::uint32_t max_depth = 300, std::uint64_t max_values = 4u << 20);

}  // namespace revkit::container::detail
