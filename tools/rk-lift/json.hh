// Minimal JSON value with sorted object keys, written in the reference
// format's canonical layout (docs/reference-format.md): byte-identical to
// tools/refdiff/refformat.py dumps().
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <ostream>
#include <string>
#include <variant>
#include <vector>

namespace rklift {

class Json {
 public:
  using Array = std::vector<Json>;
  using Object = std::map<std::string, Json>;  // std::map keeps keys sorted

  Json() : v_(nullptr) {}
  Json(std::nullptr_t) : v_(nullptr) {}
  Json(bool b) : v_(b) {}
  Json(int i) : v_(static_cast<std::int64_t>(i)) {}
  Json(unsigned u) : v_(static_cast<std::uint64_t>(u)) {}
  Json(std::int64_t i) : v_(i) {}
  Json(std::uint64_t u) : v_(u) {}
  Json(const char *s) : v_(std::string(s)) {}
  Json(std::string s) : v_(std::move(s)) {}
  Json(Array a) : v_(std::move(a)) {}
  Json(Object o) : v_(std::move(o)) {}
  Json(double d) : v_(d) {}

  // Parses one JSON document. Integers stay exact (int64 or uint64);
  // numbers with a fraction or exponent become doubles. Throws JsonError.
  static Json parse(std::string_view text);

  bool is_null() const { return std::holds_alternative<std::nullptr_t>(v_); }
  bool is_object() const { return std::holds_alternative<Object>(v_); }
  bool is_array() const { return std::holds_alternative<Array>(v_); }
  bool is_string() const { return std::holds_alternative<std::string>(v_); }
  bool is_bool() const { return std::holds_alternative<bool>(v_); }
  bool is_number() const;
  const Object &object() const;
  const Array &array() const;
  const std::string &str() const;
  bool boolean() const;
  std::int64_t int64() const;
  std::uint64_t uint64() const;
  // Member lookup on an object; null when absent or not an object.
  const Json *find(const std::string &key) const;
  const Json &operator[](const std::string &key) const;  // null value when absent

  // Compact, like json.dumps(sort_keys=True, separators=(",", ":"),
  // ensure_ascii=True).
  std::string compact() const;

  // A top-level document: one key per line, and each element of a top-level
  // array on its own compact line. Arrays must already be sorted.
  void write_document(std::ostream &os) const;

 private:
  void write_compact(std::string &out) const;
  std::variant<std::nullptr_t, bool, std::int64_t, std::uint64_t, std::string, Array, Object, double> v_;
};

std::string hex(std::uint64_t v);

// Appends `s` as a JSON string literal escaped like Python's json.dumps with
// ensure_ascii (what Json::compact() writes for a string).
void append_quoted(std::string &out, std::string_view s);
// Appends "0x..." (lowercase, no padding), as hex() returns.
void append_hex(std::string &out, std::uint64_t v);

// Writes a top-level document in the same canonical layout as
// Json::write_document() and refformat.py dumps(), without holding it in
// memory: keys must come in sorted order, and the elements of `memory`,
// `functions` and `instructions` one at a time, already sorted. Output is
// buffered and flushed in large writes.
class DocumentWriter {
 public:
  explicit DocumentWriter(std::ostream &os);
  // A key whose value is written compact on its line.
  void field(std::string_view key, const Json &value);
  // A key whose array is written one element per line.
  void begin_array(std::string_view key);
  // Starts the next element of the open array and returns the buffer to
  // append its compact JSON to.
  std::string &element();
  void end_array();
  // Closes the document and flushes. Returns false if the stream failed.
  bool finish();

 private:
  void key(std::string_view k);
  void flush_if_full();

  std::ostream &os_;
  std::string buf_;
  std::string last_key_;
  bool any_key_ = false;
  bool in_array_ = false;
  bool any_element_ = false;
};

class JsonError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

// "0x1f" -> 31. Throws JsonError.
std::uint64_t parse_hex_string(const std::string &s);

}  // namespace rklift
