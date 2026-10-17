// Register values over address ranges (docs/api.md, "Register values";
// Ghidra's Set Register Values and its register manager): the value a
// register holds wherever code runs in a range, which analysis and the
// decompiler take as known there. MIPS gp, the PowerPC TOC (r2) and small
// data bases (r13, r2) are the usual ones.
//
// Two sources, painted in this order (the later wins where they overlap):
//   - analysis's defaults from the loader (ProgramInfo::register_defaults:
//     MIPS _gp, the PowerPC 64 TOC base or .opd descriptors, _SDA_BASE_);
//   - the assertions: REGISTER_VALUE@first sub "<register>:<hex length>",
//     value the value in hex, or "none" (no value there: it clears what is
//     under it). They are ordered (facts::AssertedOrder) like MUTABILITY:
//     where two overlap, each byte goes to the live one of the highest
//     precedence, then the most recent.
//
//   analysis.register_values           the painted map, per register
//   analysis.register_values.slots     the registers with a value anywhere
//                                      (what a flow checks first)
//   analysis.register_values.bucket    the values over one 64 KiB bucket of
//                                      the key index (what a flow reads)
//   analysis.register_values.at        the values at one address (what the
//                                      decompiler reads at an entry)
//
// How they are used: a flow's constants (data references, FlowGraph::
// data_refs) start with the values at its entry, and a register with a
// value at an instruction that the flow doesn't know (never written on the
// path, written with an unknown value, or forgotten at a call) reads as
// that value there; references found only through them are the flow's
// references too (FlowGraph::refs). The decompiler is given the values at
// a function's entry as tracked registers (getTrackedRegisters).
// Context registers (TMode, ISA_MODE) aren't values: they decode code, which
// the listing's Disassemble ARM / Thumb sets.
#pragma once

#include "revkit/analysis/analysis.h"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::analysis {

// ---- assertions ----

inline constexpr std::string_view kRegisterValueNone = "none";

// The REGISTER_VALUE sub of a range: "<register>:<hex length>".
std::string register_value_sub(std::string_view reg, std::uint64_t length);
struct RegisterValueSub {
  std::string reg;
  std::uint64_t length = 0;
};
std::optional<RegisterValueSub> parse_register_value_sub(std::string_view sub);
// The value text: the value in lower-case hex, or "none".
std::string register_value_text(std::optional<std::uint64_t> value);
// nullopt if it doesn't read; a nullopt inside for "none".
std::optional<std::optional<std::uint64_t>> parse_register_value_text(std::string_view text);

// The register of that name in the program's language (register space
// only), as the language spells it; the name is matched exactly, then
// ignoring case. Null for none, or for a context register (contextreg, a
// context variable). lift::initialize() must have been called.
struct NamedRegister {
  std::string name;
  RegisterSlot slot;
};
std::optional<NamedRegister> find_register(const ProgramInfo &info, std::string_view name);
// The language's register names that values may be set on: the register
// space's, without sub-registers' aliases of the same storage beyond the
// first name and without hidden or context ones, by offset then size.
const std::vector<NamedRegister> &value_registers(const ProgramInfo &info);

// ---- the painted map ----

struct RegisterValuePiece {
  std::uint64_t first = 0, last = 0;
  std::uint64_t value = 0;
  // Where it comes from: an assertion (its key: start and sub), or
  // analysis's default (`origin`, a RegisterDefault::origin).
  bool asserted = false;
  std::uint64_t start = 0;
  std::string sub;
  std::string origin;

  void encode(facts::Encoder &e) const;
  static RegisterValuePiece decode(facts::Decoder &d);
  friend bool operator==(const RegisterValuePiece &, const RegisterValuePiece &) = default;
};

struct RegisterRanges {
  std::string name;
  RegisterSlot slot;
  std::vector<RegisterValuePiece> pieces;  // sorted, disjoint

  const RegisterValuePiece *at(std::uint64_t a) const;
  void encode(facts::Encoder &e) const;
  static RegisterRanges decode(facts::Decoder &d);
  friend bool operator==(const RegisterRanges &, const RegisterRanges &) = default;
};

struct RegisterValueMap {
  std::vector<RegisterRanges> registers;  // by name; only those with a piece

  const RegisterRanges *find(std::string_view name) const;
  void encode(facts::Encoder &e) const;
  static RegisterValueMap decode(facts::Decoder &d);
  friend bool operator==(const RegisterValueMap &, const RegisterValueMap &) = default;
};

struct RegisterValues {
  static constexpr std::string_view name = "analysis.register_values";
  static constexpr std::uint32_t version = 1;
  using Key = ProgramKey;
  using Value = RegisterValueMap;
  static Value compute(facts::QueryContext &ctx, const Key &key);
  static std::string describe(const Key &k) { return k.id; }
};

struct RegisterValueSlots {
  static constexpr std::string_view name = "analysis.register_values.slots";
  static constexpr std::uint32_t version = 1;
  using Key = ProgramKey;
  using Value = std::vector<RegisterSlot>;  // sorted
  static Value compute(facts::QueryContext &ctx, const Key &key);
  static std::string describe(const Key &k) { return k.id; }
};

// One register's value over part of a bucket.
struct RegisterValueSpan {
  std::uint64_t first = 0, last = 0;
  RegisterSlot slot;
  std::uint64_t value = 0;

  void encode(facts::Encoder &e) const;
  static RegisterValueSpan decode(facts::Decoder &d);
  friend bool operator==(const RegisterValueSpan &, const RegisterValueSpan &) = default;
};

struct RegisterValueBucket {
  static constexpr std::string_view name = "analysis.register_values.bucket";
  static constexpr std::uint32_t version = 1;
  using Key = Location;  // address = the bucket index (address >> facts::kBucketShift)
  using Value = std::vector<RegisterValueSpan>;  // by first, then slot
  static Value compute(facts::QueryContext &ctx, const Key &key);
  static std::string describe(const Key &k) { return analysis::describe(k); }
};

// The registers the map decides at one address: those with a value there
// and those with a default (ProgramInfo::register_defaults) anywhere,
// nullopt where they have none here (the user cleared it). By name.
struct RegisterValuesAt {
  static constexpr std::string_view name = "analysis.register_values.at";
  static constexpr std::uint32_t version = 1;
  using Key = Location;
  using Value = std::vector<std::pair<std::string, std::optional<std::uint64_t>>>;
  static Value compute(facts::QueryContext &ctx, const Key &key);
  static std::string describe(const Key &k) { return analysis::describe(k); }
};

// What a flow reads: the value a register slot has at an address, through
// the buckets it touches (read once each). Empty (no lookups) when the
// program has no values.
class RegisterValueReader {
 public:
  RegisterValueReader(facts::QueryContext &ctx, const ProgramKey &program);
  bool empty() const { return slots_->empty(); }
  // The value of the register stored at [offset, offset + size) at `a`:
  // the whole of a slot with a value, or (`big_endian`) its low part.
  std::optional<std::uint64_t> value(std::uint64_t a, std::uint64_t offset, std::uint32_t size, bool big_endian);
  // Every slot with a value at `a`.
  std::vector<std::pair<RegisterSlot, std::uint64_t>> values_at(std::uint64_t a);

 private:
  const std::vector<RegisterValueSpan> &bucket(std::uint64_t index);
  facts::QueryContext &ctx_;
  const ProgramKey &program_;
  facts::Ref<std::vector<RegisterSlot>> slots_;
  std::vector<std::pair<std::uint64_t, facts::Ref<std::vector<RegisterValueSpan>>>> buckets_;
};

void register_register_value_queries(facts::Engine &engine);  // called by register_queries

}  // namespace revkit::analysis
