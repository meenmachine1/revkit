// The value-type lattice of prototype inference, and prototypes over it.
//
// A VType is what inference knows about one value (a parameter or a return
// value): nothing but its size (`unknown`), or an integer of some size and
// signedness, a plain `char`, a bool, a float, a pointer (to another VType),
// a named struct (from a library signature or a debug-info type), or code.
//
// The lattice orders types by how much they say. `join` combines two
// observations of the same value into the most specific type consistent
// with both, `widen` gives up on a value that keeps changing; see
// vtype.cc for the rules. Types print in Ghidra's notation (`uint`,
// `char *`, `undefined8`), which is what the reference format and
// tools/rk-debuginfo/protonorm.py compare.
#pragma once

#include "revkit/facts/codec.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace revkit::infer {

enum class Meta : std::uint8_t {
  unknown,  // only the size is known ("undefinedN")
  void_,
  bool_,
  int_,     // integer, `sign` says whether its signedness is known
  char_,    // C's plain char (1 byte)
  float_,
  pointer,  // `pointee` holds the target (one element)
  struct_,  // a named struct or union, opaque
  code,     // a function (only behind a pointer)
};

enum class Sign : std::uint8_t { unknown, is_signed, is_unsigned };

// How confident a rule is in a type: a weak type is a default or a guess
// that any real evidence overrides.
enum class Strength : std::uint8_t { none, weak, local, strong };

// Sizes and spellings of the target's C types.
struct DataOrg {
  std::uint8_t pointer_size = 8;
  std::uint8_t long_size = 8;  // 4 on LLP64 (Windows)
  bool char_signed = true;
};

struct Prototype;

struct VType {
  Meta meta = Meta::unknown;
  std::uint8_t size = 0;  // bytes; 0 when not known (unknown pointee)
  Sign sign = Sign::unknown;
  bool long_long = false;  // an 8-byte integer spelled `long long` where long is 8 bytes too
  std::string name;        // struct_: tag name; code: "..." when variadic
  // pointer: exactly one element, the target. code: its signature when
  // known, return type first, then the parameters.
  std::vector<VType> pointee;

  static VType unknown(std::uint8_t size) { return {Meta::unknown, size, Sign::unknown, false, {}, {}}; }
  static VType void_type() { return {Meta::void_, 0, Sign::unknown, false, {}, {}}; }
  static VType boolean() { return {Meta::bool_, 1, Sign::unknown, false, {}, {}}; }
  static VType character() { return {Meta::char_, 1, Sign::unknown, false, {}, {}}; }
  static VType integer(std::uint8_t size, Sign sign, bool long_long = false) {
    return {Meta::int_, size, sign, long_long, {}, {}};
  }
  static VType floating(std::uint8_t size) { return {Meta::float_, size, Sign::unknown, false, {}, {}}; }
  static VType structure(std::string name) { return {Meta::struct_, 0, Sign::unknown, false, std::move(name), {}}; }
  static VType code_type() { return {Meta::code, 0, Sign::unknown, false, {}, {}}; }
  // A function of the given prototype (printed _func_int_int_int).
  static VType code_of(const Prototype &p);
  static VType pointer_to(VType target, std::uint8_t size) {
    VType p{Meta::pointer, size, Sign::unknown, false, {}, {}};
    p.pointee.push_back(std::move(target));
    return p;
  }

  bool is_unknown() const { return meta == Meta::unknown; }
  bool is_void() const { return meta == Meta::void_; }
  bool is_pointer() const { return meta == Meta::pointer && !pointee.empty(); }
  const VType &target() const { return pointee.front(); }
  // Pointer depth and innermost target.
  int depth() const;
  const VType &innermost() const;
  // Whether the type says anything beyond its size.
  bool informative() const;

  friend bool operator==(const VType &, const VType &) = default;

  void encode(facts::Encoder &e) const;
  static VType decode(facts::Decoder &d);
};

// Ghidra's spelling: "int", "ulong", "char * *", "undefined8", "_IO_FILE *".
std::string print(const VType &t, const DataOrg &org);

// Parses the spelling print() produces (and the signature database's):
// a base name followed by stars. Unknown base names are structs.
std::optional<VType> parse_type(std::string_view text, const DataOrg &org);

// The most specific type consistent with both (see vtype.cc). `a` wins ties.
VType join(const VType &a, const VType &b);

// What remains of a type when observations disagree too often: the size,
// and for pointers that it is a pointer.
VType widen(const VType &t);

struct Prototype {
  VType ret = VType::void_type();
  std::vector<VType> params;
  bool varargs = false;
  // Where it came from: "libc", "self", "merged", ...
  std::string source;

  friend bool operator==(const Prototype &, const Prototype &) = default;

  // "int name(char * param_1, uint param_2)" in Ghidra's notation. Unnamed
  // parameters are param_1, param_2, ... as Ghidra names them.
  std::string print(const std::string &name, const DataOrg &org) const;

  void encode(facts::Encoder &e) const;
  static Prototype decode(facts::Decoder &d);
};

}  // namespace revkit::infer
