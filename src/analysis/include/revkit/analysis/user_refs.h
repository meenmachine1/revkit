// Equates and user references as the fact store holds them (docs/api.md,
// "Equates and user references"): the EQUATE and REFERENCE keys' subs and
// values, and how a scalar shows in a format. Shared by discovery (which
// follows user call and jump references), the backend (keys, the listing,
// xrefs, the decompiler's inputs) and the archive check.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace revkit::analysis {

// The API's ScalarFormat numbers.
enum class ScalarFormat : std::uint8_t {
  none = 0,
  hex = 1,
  signed_dec = 2,
  unsigned_dec = 3,
  octal = 4,
  binary = 5,
  chr = 6,
  flt = 7,
};

// How one scalar shows: a format, an equate's name, or an enum member
// (the enum's type hash and the member, whose name is `name`).
struct OperandDisplay {
  ScalarFormat format = ScalarFormat::none;
  std::string name;
  std::string enum_type;
  std::string member;

  bool equate() const { return !name.empty(); }
  friend bool operator==(const OperandDisplay &, const OperandDisplay &) = default;
};

// EQUATE values: "f:<format number>", "e:<name>", "m:<enum hash>:<member>";
// "" is the disassembler's display.
std::string encode_operand_display(const OperandDisplay &d);
std::optional<OperandDisplay> parse_operand_display(std::string_view text);

// EQUATE subs: "<operand>:<hex value>", or "h<hex hash>:<hex value>" for a
// decompiler constant no operand holds (operand -1, `hash` set).
struct EquateSub {
  int operand = -1;
  std::uint64_t hash = 0;
  std::uint64_t value = 0;
};
std::string equate_sub(int operand, std::uint64_t hash, std::uint64_t value);
std::optional<EquateSub> parse_equate_sub(std::string_view sub);

// Whether a scalar of `bits` (0: 64) holding `a` is the value `b`: equal,
// or equal in its low `bits` (a sign- or zero-extended form of it).
bool scalar_matches(std::uint64_t a, std::uint64_t b, unsigned bits);

// The text a scalar of `bits` bits shows as in a format, as Ghidra's
// Convert actions print it: 0x41, -16, 65, 101o, 1000001b, 'A', 1.5.
// "" where the format can't show it (a float of a width other than 32 or
// 64 bits) or for ScalarFormat::none.
std::string format_scalar(std::uint64_t value, unsigned bits, ScalarFormat f);

// The API's ReferenceType numbers.
enum class UserRefType : std::uint8_t {
  data = 1,
  read = 2,
  write = 3,
  call = 4,
  jump = 5,
  computed_call = 6,
  computed_jump = 7,
};

// One REFERENCE key: from the instruction at the key's address, operand
// `operand` (-1: the instruction as a whole), to `to`.
struct UserRef {
  int operand = -1;
  std::uint64_t to = 0;
  UserRefType type = UserRefType::data;
  bool primary = false;
  // The reference is deleted: the user's at this key, and analysis's from
  // the instruction to `to`.
  bool remove = false;

  bool is_call() const { return type == UserRefType::call || type == UserRefType::computed_call; }
  bool is_jump() const { return type == UserRefType::jump || type == UserRefType::computed_jump; }
  friend bool operator==(const UserRef &, const UserRef &) = default;
};

// REFERENCE subs: "<operand>:<hex to>" or "i:<hex to>".
std::string user_ref_sub(int operand, std::uint64_t to);
// REFERENCE values: "<type number>" then "p" when primary; "remove".
std::string encode_user_ref(const UserRef &r);
std::optional<UserRef> parse_user_ref(std::string_view sub, std::string_view value);

}  // namespace revkit::analysis
