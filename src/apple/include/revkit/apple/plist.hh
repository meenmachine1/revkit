// Property lists (docs/apple-apps.md): XML ("<plist>") and binary
// ("bplist00") ones, read into one value tree, as CoreFoundation's
// CFPropertyList reads them, for hostile input:
//
//   - the input is at most Limits::max_input bytes;
//   - nesting is at most Limits::max_depth;
//   - a binary plist's objects can be shared (a DAG) or cyclic: a cycle is
//     refused, and every value made (shared ones once per use) counts
//     against Limits::max_values and its bytes against
//     Limits::max_value_bytes, so a small file can't expand without bound.
//
// NSKeyedArchiver archives are property lists too: keyed_archive.hh
// resolves their objects. OpenStep (text) plists and JSON aren't read.
#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::apple {

// Malformed or unsupported input.
class Error : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

// A limit was reached (too deep, too many values, too large).
class LimitError : public Error {
 public:
  using Error::Error;
};

struct Limits {
  std::uint64_t max_input = 64ull << 20;
  std::uint32_t max_depth = 128;
  std::uint64_t max_values = 1u << 21;
  // Bytes of strings, data and keys made.
  std::uint64_t max_value_bytes = 256ull << 20;
};

struct DictEntry;

struct Value {
  enum class Type : std::uint8_t { null, boolean, integer, real, date, data, string, array, dict, uid };
  Type type = Type::null;
  bool boolean = false;
  // An integer: `integer` when it fits int64_t, else `unsigned_value` with
  // `big` set (a binary plist's 128-bit integers keep their low 64 bits,
  // as CoreFoundation reads them).
  std::int64_t integer = 0;
  std::uint64_t unsigned_value = 0;
  bool big = false;
  // A real; a date as seconds since 2001-01-01 00:00 UTC (CFAbsoluteTime).
  double real = 0;
  // A string (UTF-8) or data (bytes).
  std::string bytes;
  // A UID (keyed archives' object references).
  std::uint64_t uid = 0;
  std::vector<Value> array;
  std::vector<DictEntry> dict;  // in file order; a repeated key keeps the last

  bool is(Type t) const { return type == t; }
  // A dictionary's value for `key`, or null.
  const Value *get(std::string_view key) const;
  // The value as a string, when it is one.
  const std::string *as_string() const { return type == Type::string ? &bytes : nullptr; }
  std::optional<std::int64_t> as_int() const;
  std::optional<bool> as_bool() const { return type == Type::boolean ? std::optional<bool>(boolean) : std::nullopt; }
  // A dictionary's string for `key` ("" when absent or not a string).
  std::string string_at(std::string_view key) const;
  // A dictionary's array of strings for `key` (a lone string is one).
  std::vector<std::string> strings_at(std::string_view key) const;

  static Value make_string(std::string s);
  static Value make_int(std::int64_t v);
  static Value make_bool(bool v);
};

struct DictEntry {
  std::string key;
  Value value;
};

enum class Format : std::uint8_t { xml, binary };

struct Parsed {
  Format format = Format::xml;
  Value root;
  // Values made, for callers that budget several documents.
  std::uint64_t values = 0;
};

// Whether the bytes start as a property list does: "bplist00", or XML
// (after a byte-order mark and white space) whose head has a <plist
// element.
std::optional<Format> sniff(std::span<const std::byte> head);

// Reads a whole property list. Error on malformed input (with what and
// where), LimitError past the limits.
Parsed parse(std::span<const std::byte> bytes, const Limits &limits = {});
Value parse_xml(std::string_view text, const Limits &limits = {}, std::uint64_t *values = nullptr);
Value parse_binary(std::span<const std::byte> bytes, const Limits &limits = {}, std::uint64_t *values = nullptr);

// A date as Unix seconds (and back): CFAbsoluteTime is from 2001-01-01.
constexpr double kAbsoluteTimeEpoch = 978307200.0;
// "2026-10-18T12:00:00Z" (XML plists' form), from a CFAbsoluteTime.
std::string iso8601(double absolute_time);
std::optional<double> parse_iso8601(std::string_view text);

// Writes a value as an XML plist (tests, and the UI's copy): strings
// escaped, data base64, dates ISO 8601. UIDs are written as CF$UID
// dictionaries, as Foundation writes them.
std::string to_xml(const Value &v);

}  // namespace revkit::apple
