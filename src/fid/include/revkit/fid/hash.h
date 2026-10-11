// Ghidra's Function ID hash (MessageDigestFidHasher with
// FunctionBodyFunctionExtentGenerator and FNV1a64MessageDigest), bit for
// bit, so revkit reads Ghidra's databases (docs/fid.md, "Hashing").
#pragma once

#include "revkit/fid/db.h"
#include "revkit/lift/sleigh_decoder.hh"

#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace revkit::fid {

// FidService's constants.
inline constexpr int kShortHashCodeUnits = 4;    // fewer instructions hash to nothing
inline constexpr int kMediumHashCodeUnits = 24;  // auto-pass functions score at least this
inline constexpr float kScoreThreshold = 14.6f;
inline constexpr float kMultiNameScoreThreshold = 30.0f;

// FNV-1a, 64 bits (generic.hash.FNV1a64MessageDigest).
class Fnv1a64 {
 public:
  void update(std::uint8_t b) {
    h_ ^= b;
    h_ *= 1099511628211ULL;
  }
  void update(std::span<const std::uint8_t> b) {
    for (std::uint8_t c : b) update(c);
  }
  void update_int(std::uint32_t v) {  // AbstractMessageDigest.update(int): big-endian
    for (int s = 24; s >= 0; s -= 8) update(static_cast<std::uint8_t>(v >> s));
  }
  std::uint64_t value() const { return h_; }

 private:
  std::uint64_t h_ = 0xcbf29ce484222325ULL;
};

// One instruction of a function's body, in address order.
struct HashUnit {
  std::uint64_t address = 0;
  std::vector<std::uint8_t> bytes;  // its bytes (FidInstruction::length of them)
  lift::FidInstruction insn;
};

struct HashOptions {
  // Instructions skipped entirely (InstructionSkipper; Ghidra has one, for
  // the processor "x86": the NOP forms compilers pad with).
  bool skip_x86_nops = false;
  // Whether a relocation touches [first, last] (inclusive addresses).
  std::function<bool(std::uint64_t first, std::uint64_t last)> relocated;
  // Whether the instruction's operand has a reference to memory, which
  // makes Ghidra's operand type an address (InstructionDB.getOperandType).
  std::function<bool(std::uint64_t address, int operand, const lift::FidObject &scalar)> address_operand;
};

// The x86 skipper's patterns (X86InstructionSkipper).
bool x86_skipped(std::span<const std::uint8_t> bytes);
// Whether a language's processor has Ghidra's x86 skipper ("x86:...").
bool skips_x86_nops(const std::string &language);

// FidHashQuad of a function from its instructions; nullopt when it has
// fewer than kShortHashCodeUnits (after skipped ones).
std::optional<HashQuad> hash_function(std::span<const HashUnit> units, const HashOptions &options);

}  // namespace revkit::fid
