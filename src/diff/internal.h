// Helpers shared by diff.features and diff.code (internal to src/diff):
// p-code opcode indexes and primes, operand kinds, masking the fields of an
// instruction's bytes that encode an address, strings at an address.
#pragma once

#include "revkit/lift/lifter.hh"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace revkit::diff::detail {

using namespace std::string_view_literals;

// Ghidra's p-code opcodes, in CPUI_ order; an opcode's index picks its
// prime for the order-free signature.
inline constexpr std::array<std::string_view, 74> kOpcodes = {
    "COPY", "LOAD", "STORE", "BRANCH", "CBRANCH", "BRANCHIND", "CALL", "CALLIND", "CALLOTHER", "RETURN",
    "INT_EQUAL", "INT_NOTEQUAL", "INT_SLESS", "INT_SLESSEQUAL", "INT_LESS", "INT_LESSEQUAL", "INT_ZEXT",
    "INT_SEXT", "INT_ADD", "INT_SUB", "INT_CARRY", "INT_SCARRY", "INT_SBORROW", "INT_2COMP", "INT_NEGATE",
    "INT_XOR", "INT_AND", "INT_OR", "INT_LEFT", "INT_RIGHT", "INT_SRIGHT", "INT_MULT", "INT_DIV", "INT_SDIV",
    "INT_REM", "INT_SREM", "BOOL_NEGATE", "BOOL_XOR", "BOOL_AND", "BOOL_OR", "FLOAT_EQUAL", "FLOAT_NOTEQUAL",
    "FLOAT_LESS", "FLOAT_LESSEQUAL", "FLOAT_NAN", "FLOAT_ADD", "FLOAT_DIV", "FLOAT_MULT", "FLOAT_SUB",
    "FLOAT_NEG", "FLOAT_ABS", "FLOAT_SQRT", "FLOAT_INT2FLOAT", "FLOAT_FLOAT2FLOAT", "FLOAT_TRUNC",
    "FLOAT_CEIL", "FLOAT_FLOOR", "FLOAT_ROUND", "MULTIEQUAL", "INDIRECT", "PIECE", "SUBPIECE", "CAST",
    "PTRADD", "PTRSUB", "SEGMENTOP", "CPOOLREF", "NEW", "INSERT", "EXTRACT", "POPCOUNT", "LZCOUNT",
    "UNIMPLEMENTED", "OTHER"};

inline std::uint32_t OpcodeIndex(std::string_view op) {
  static const std::unordered_map<std::string_view, std::uint32_t> index = [] {
    std::unordered_map<std::string_view, std::uint32_t> m;
    for (std::uint32_t i = 0; i < kOpcodes.size(); ++i) m.emplace(kOpcodes[i], i);
    return m;
  }();
  auto it = index.find(op);
  return it == index.end() ? static_cast<std::uint32_t>(kOpcodes.size() - 1) : it->second;
}

inline std::uint64_t Prime(std::uint32_t i) {
  static const std::vector<std::uint64_t> primes = [] {
    std::vector<std::uint64_t> p;
    for (std::uint64_t n = 3; p.size() < kOpcodes.size(); n += 2) {
      bool prime = true;
      for (std::uint64_t q : p)
        if (q * q > n) break;
        else if (n % q == 0) prime = false;
      if (prime) p.push_back(n);
    }
    return p;
  }();
  return primes[i];
}

// What an operand is, for F2: never a register number or an address.
enum class Kind : std::uint8_t { constant, address, reg, unique, memory, other };

inline Kind KindOf(const lift::Varnode &v, const std::string &code_space) {
  if (v.space == "const"sv) return Kind::constant;
  if (v.space == "register"sv) return Kind::reg;
  if (v.space == "unique"sv) return Kind::unique;
  if (v.space == code_space) return Kind::memory;
  return Kind::other;
}

inline std::uint32_t Hash32(std::uint64_t h) { return static_cast<std::uint32_t>(h ^ (h >> 32)); }

inline std::int64_t Signed(std::uint64_t value, std::uint32_t size) {
  if (size == 0 || size >= 8) return static_cast<std::int64_t>(value);
  const unsigned shift = 64 - 8 * size;
  return static_cast<std::int64_t>(value << shift) >> shift;
}

// Little- or big-endian bytes of the low `size` bytes of v.
inline std::array<std::byte, 8> Encoded(std::uint64_t v, unsigned size, bool big_endian) {
  std::array<std::byte, 8> out{};
  for (unsigned i = 0; i < size; ++i) {
    const unsigned shift = big_endian ? 8 * (size - 1 - i) : 8 * i;
    out[i] = static_cast<std::byte>((v >> shift) & 0xff);
  }
  return out;
}

// Masks the field of `bytes` that encodes v (absolute, or relative to the
// instruction or its end), if there is one; false when none does.
inline bool MaskField(std::vector<std::byte> &bytes, std::vector<bool> &masked, std::uint64_t v, std::uint64_t addr,
               std::uint32_t own_length, bool big_endian, unsigned pointer_size) {
  struct Candidate {
    std::uint64_t value;
    unsigned size;
  };
  std::vector<Candidate> c;
  if (pointer_size >= 8) c.push_back({v, 8});
  c.push_back({v, 4});
  for (std::uint64_t base : {addr + own_length, addr, addr + 4, addr + 8}) c.push_back({v - base, 4});
  bool found = false;
  for (const Candidate &k : c) {
    if (bytes.size() < k.size) continue;
    const auto enc = Encoded(k.value, k.size, big_endian);
    for (std::size_t i = 0; i + k.size <= bytes.size(); ++i) {
      if (!std::equal(enc.begin(), enc.begin() + k.size, bytes.begin() + static_cast<std::ptrdiff_t>(i))) continue;
      for (unsigned j = 0; j < k.size; ++j) masked[i + j] = true;
      found = true;
    }
    if (found) return true;
  }
  return false;
}

// A NUL-terminated printable ASCII string of at least 4 characters at the
// bytes' start: its text.
inline std::optional<std::string> AsciiString(std::span<const std::byte> b) {
  std::string s;
  for (std::byte x : b) {
    const auto c = std::to_integer<unsigned char>(x);
    if (c == 0) return s.size() >= 4 ? std::optional(s) : std::nullopt;
    if (!(c >= 0x20 && c < 0x7f) && c != '\t' && c != '\n' && c != '\r') return std::nullopt;
    s.push_back(static_cast<char>(c));
  }
  return s.size() >= 64 ? std::optional(s) : std::nullopt;  // long: truncated, still a string
}

}  // namespace revkit::diff::detail
