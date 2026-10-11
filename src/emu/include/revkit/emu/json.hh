// A small JSON value for machine descriptions (docs/firmware-emulation.md):
// parsing with line:column errors, `//` and `/* */` comments, exact 64-bit
// integers (and numbers written as hex strings, "0x1000"), and a writer
// that keeps object keys in the order they were added.
#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace revkit::emu::json {

class Error : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

class Value {
 public:
  enum class Type : std::uint8_t { null, boolean, integer, number, string, array, object };
  using Member = std::pair<std::string, Value>;

  Value() = default;
  static Value boolean(bool b);
  static Value integer(std::int64_t v);
  static Value unsigned_integer(std::uint64_t v);
  static Value number(double d);
  static Value string(std::string s);
  static Value array();
  static Value object();

  Type type() const { return type_; }
  bool is_null() const { return type_ == Type::null; }
  bool is_object() const { return type_ == Type::object; }
  bool is_array() const { return type_ == Type::array; }
  bool is_string() const { return type_ == Type::string; }
  bool is_bool() const { return type_ == Type::boolean; }
  bool is_integer() const { return type_ == Type::integer; }

  bool as_bool() const { return b_; }
  const std::string &as_string() const { return s_; }
  // Integers as written (negative ones wrap); `negative` says which.
  std::uint64_t as_u64() const { return u_; }
  bool negative() const { return neg_; }
  double as_double() const { return type_ == Type::integer ? (neg_ ? -static_cast<double>(~u_ + 1) : static_cast<double>(u_)) : d_; }

  const std::vector<Value> &items() const { return items_; }
  std::vector<Value> &items() { return items_; }
  const std::vector<Member> &members() const { return members_; }
  // The member named `key`, or null.
  const Value *find(std::string_view key) const;
  Value &set(std::string key, Value v);  // replaces or appends
  Value &push(Value v);

  // Where the value starts in the parsed text (1-based), for messages.
  int line = 0, column = 0;

  // Parses one document; throws Error("line:col: ...").
  static Value parse(std::string_view text);
  // Pretty-printed with two-space indentation; small arrays of scalars on one line.
  std::string dump(int indent = 0) const;
  // Compact, on one line.
  std::string compact() const;

 private:
  Type type_ = Type::null;
  bool b_ = false;
  bool neg_ = false;
  std::uint64_t u_ = 0;
  double d_ = 0;
  std::string s_;
  std::vector<Value> items_;
  std::vector<Member> members_;
};

// "line:col" of a value, for messages.
std::string where(const Value &v);
std::string quote(std::string_view s);

}  // namespace revkit::emu::json
