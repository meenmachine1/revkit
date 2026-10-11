// Debugger expressions (docs/debugger.md, "Expressions"): what watches,
// value hovers and breakpoint conditions evaluate. C's operators over
// registers, program symbols, a frame's variables and target memory, with
// the program's types: `$RSP + 8`, `*(int *)($RBP - 0x14)`, `ctx->buf[2]`,
// `n == 5 && counter > 3`. Numbers are C's (decimal, or hex with 0x).
//
// Parsing is separate from evaluation, so a breakpoint's condition is
// parsed once and evaluated at every hit. Names are resolved through a
// Context at evaluation; the parser asks only whether a name is a type
// (for casts).
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace revkit::debug::expr {

class ExprError : public std::runtime_error {
 public:
  ExprError(const std::string &what, std::size_t at = 0) : std::runtime_error(what), at(at) {}
  std::size_t at;  // character offset in the text
};

struct Type;
using TypeP = std::shared_ptr<const Type>;

struct Field {
  std::string name;
  std::uint64_t offset = 0;  // bytes; a bitfield's first byte
  std::uint32_t bit_offset = 0, bit_size = 0;
  std::string type_hash;  // resolved through the TypeSource when `type` is null
  TypeP type;
};

struct Type {
  enum class Kind : std::uint8_t { void_, bool_, int_, uint_, char_, float_, pointer, array, struct_, union_, enum_, function, undefined };
  Kind kind = Kind::undefined;
  std::uint64_t size = 0;
  std::string name;  // its C spelling: "int", "struct foo *", "undefined4"
  // A pointer's target or an array's element: `target`, else by hash.
  TypeP target;
  std::string target_hash;
  std::uint64_t count = 0;  // array elements
  std::vector<Field> fields;
  std::vector<std::pair<std::int64_t, std::string>> enumerators;
  bool is_signed() const;
  bool scalar() const;
};

// The program's types, by content hash and by name ("struct foo", "foo").
class TypeSource {
 public:
  virtual ~TypeSource() = default;
  virtual TypeP by_hash(const std::string &hash) = 0;  // null: unknown
  virtual TypeP by_name(const std::string &name) = 0;  // null: unknown
};

// C's and Ghidra's built-in names ("int", "unsigned long", "uint32_t",
// "undefined4", "size_t"), for a data model with this pointer size; null
// for others.
TypeP builtin(const std::string &name, unsigned pointer_size);
TypeP integer(std::uint64_t size, bool is_signed);
TypeP undefined(std::uint64_t size);
TypeP pointer_to(TypeP target, unsigned pointer_size);

struct Value {
  TypeP type;
  std::vector<std::uint8_t> bytes;  // in target order; empty when not known
  // Where it lives: memory (runtime), a register, or nowhere (computed).
  std::optional<std::uint64_t> address;
  std::string reg;
  // Not known: why ("memory at 0x… was not recorded", "RAX is not recovered in frame #2").
  std::string unknown;
  bool truncated = false;  // a large array: only its start was read
};

// What evaluation reads. Every callback may be unset.
struct Context {
  // A name's value: a variable of the frame's function, a register (any
  // case), a program symbol; `register_only` for `$name`. A value with an
  // `address` and no bytes is read from memory.
  std::function<std::optional<Value>(const std::string &name, bool register_only)> lookup;
  // Target memory at a runtime address; the bytes it could read, from the start.
  std::function<std::size_t(std::uint64_t address, std::span<std::uint8_t> out)> read;
  // "main+0x10" for a runtime address, or "".
  std::function<std::string(std::uint64_t address)> symbolize;
  TypeSource *types = nullptr;
  unsigned pointer_size = 8;
  bool big_endian = false;
  std::size_t max_read = 4096;  // bytes of one value read at most
};

struct Node;
using NodeP = std::shared_ptr<const Node>;

// A parsed expression.
class Expression {
 public:
  // Throws ExprError. `is_type`: whether a bare identifier names a type
  // (so `(foo *)p` is a cast); unset: only built-in names and struct/union/enum tags.
  static Expression parse(const std::string &text, const std::function<bool(const std::string &)> &is_type = {});
  // Throws ExprError (an unknown name, a field a type doesn't have,
  // dereferencing an unknown value, …).
  Value evaluate(Context &ctx) const;
  const std::string &text() const { return text_; }

 private:
  std::string text_;
  NodeP root_;
};

// Reads a value's bytes as an unsigned or a signed integer (at most 8 bytes).
std::uint64_t as_u64(const Value &v, bool big_endian);
// A condition's truth: non-zero. Throws ExprError when it isn't known.
bool truthy(const Value &v, bool big_endian);

struct Formatted {
  std::string text;  // typed: "42", "0x5555… <main+0x10>", "{a = 1, b = 2}", "3.5", "'A'"
  std::string hex;   // a scalar's bytes as one hex number; "" for aggregates
  struct Child {
    std::string name, text, type;
    std::optional<std::uint64_t> address;
  };
  std::vector<Child> children;  // a struct's fields, an array's elements (64 at most)
};
// `depth`: how many levels of nested structs and arrays the text spells out.
Formatted format(const Value &v, Context &ctx, int depth = 2);

// A type name as a cast spells it ("unsigned int", "struct foo", "foo"),
// through the TypeSource then the built-ins; null when unknown.
TypeP resolve_type_name(const std::string &name, Context &ctx);

}  // namespace revkit::debug::expr
