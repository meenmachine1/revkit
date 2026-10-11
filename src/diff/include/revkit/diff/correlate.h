// Inside a matched pair: which blocks and instructions of function A
// correspond to which of function B (docs/diff.md "Inside a function";
// design in docs/diff/design.md, section 3).
//
// diff.code(program, entry) describes one function's instructions as the
// correlation compares them, per instruction:
//   kind   the p-code's opcodes with its operands' kinds and sizes: no
//          constants, registers or addresses (F2's tokens without values)
//   exact  the bytes with every field that encodes an address outside the
//          function masked (F1 per instruction; the p-code with its
//          constants where the field isn't byte-aligned), with what the
//          external targets are (a function, an import by name, data)
// and its basic blocks (as GetFunctionGraph cuts them: calls don't end
// blocks, calls to no-return functions do) with their edges.
//
// correlate(a, b) is a port of the idea of Ghidra's
// HashedFunctionAddressCorrelation, over those tokens instead of mnemonics:
//   1. n-grams of consecutive instructions within a block, longest first
//      (16 down to 1), on `exact` and then on `kind`: an n-gram whose hash
//      occurs exactly once on each side matches its instructions;
//      matches extend forward and backward along their blocks while the
//      tokens agree.
//   2. Blocks pair by the instruction matches between them (most first,
//      one to one), then through matched neighbours: a pair's unpaired
//      successors (and predecessors) of the same edge kind, one on each
//      side, pair; entry blocks pair. Split and merged blocks (a block of
//      A whose matches lead to two of B) stay together as a cluster.
//   3. Within each cluster, instructions align by LCS: equal `exact`
//      tokens (and branches within the function to corresponding
//      instructions) are EQUAL; in the gaps between them, equal `kind` tokens are
//      CHANGED (same instruction, other operands); what is left of a gap
//      pairs in order as CHANGED (a replaced instruction), the rest is
//      DELETED (only in A) or INSERTED (only in B).
// Nothing assumes equal addresses: code that moved correlates the same.
// The result is deterministic (indexes and addresses order everything)
// and cheap: linear in the function's size outside the LCS of each
// cluster's differing middle.
//
// retarget() then applies the session's matches: an EQUAL pair whose call
// or jump leaves for functions that don't match each other (a retargeted
// call: the same masked bytes) becomes CHANGED. diff.correlation memoizes
// correlate() per pair; retarget() is cheap and runs per read.
#pragma once

#include "revkit/analysis/analysis.h"
#include "revkit/facts/engine.h"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::diff {

// A reference an instruction makes outside its function.
struct CodeRef {
  enum class Kind : std::uint8_t { call = 1, jump = 2, data = 3 };
  Kind kind = Kind::data;
  std::uint64_t to = 0;
  std::uint32_t string = 0;  // data: the string's content hash when it reads a string

  void encode(facts::Encoder &e) const;
  static CodeRef decode(facts::Decoder &d);
  friend bool operator==(const CodeRef &, const CodeRef &) = default;
};

struct CodeInsn {
  std::uint64_t address = 0;
  std::uint32_t length = 0;
  std::uint32_t block = 0;  // index in FunctionCode::blocks
  std::uint64_t kind = 0;
  std::uint64_t exact = 0;
  std::uint64_t raw = 0;  // the bytes as they are
  std::string mnemonic;
  std::vector<CodeRef> refs;
  // Branch and jump targets within the function (instruction indexes):
  // the displacement isn't part of `exact`, these must correspond instead.
  std::vector<std::uint32_t> local;

  void encode(facts::Encoder &e) const;
  static CodeInsn decode(facts::Decoder &d);
  friend bool operator==(const CodeInsn &, const CodeInsn &) = default;
};

// How control goes from a block to another of the same function.
enum class EdgeKind : std::uint8_t { fall = 1, taken = 2, jump = 3, switch_case = 4 };

struct CodeEdge {
  std::uint32_t to = 0;
  EdgeKind kind = EdgeKind::fall;

  void encode(facts::Encoder &e) const;
  static CodeEdge decode(facts::Decoder &d);
  friend bool operator==(const CodeEdge &, const CodeEdge &) = default;
};

struct CodeBlock {
  std::uint32_t first = 0, last = 0;  // instruction indexes, inclusive
  std::vector<CodeEdge> succ;         // by target block, then kind

  void encode(facts::Encoder &e) const;
  static CodeBlock decode(facts::Decoder &d);
  friend bool operator==(const CodeBlock &, const CodeBlock &) = default;
};

struct FunctionCode {
  std::uint64_t entry = 0;
  std::uint32_t entry_block = 0;
  std::vector<CodeInsn> insns;  // by address
  std::vector<CodeBlock> blocks;  // by address

  void encode(facts::Encoder &e) const;
  static FunctionCode decode(facts::Decoder &d);
  friend bool operator==(const FunctionCode &, const FunctionCode &) = default;
};

// diff.code(program, entry). A Location that isn't a function's entry
// gives no instructions.
struct Code {
  static constexpr std::string_view name = "diff.code";
  static constexpr std::uint32_t version = 2;  // 2: local targets
  using Key = analysis::Location;
  using Value = FunctionCode;
  static Value compute(facts::QueryContext &ctx, const Key &key);
  static std::string describe(const Key &k) { return analysis::describe(k); }
  static std::size_t weight(const Value &v) { return sizeof(Value) + v.insns.capacity() * (sizeof(CodeInsn) + 16) + v.blocks.capacity() * 48; }
};

// An instruction's standing. Values are the API's DiffLineStatus numbers.
enum class InsnStatus : std::uint8_t {
  equal = 1,     // the same instruction (masked bytes, matching targets)
  changed = 2,   // corresponds to an instruction of the other side that differs
  inserted = 3,  // only in B
  deleted = 4,   // only in A
};

// A block's standing. Values are the API's DiffBlockStatus numbers.
enum class BlockStatus : std::uint8_t {
  unchanged = 1,  // every instruction equal, both ways
  modified = 2,   // corresponds to code on the other side, not all equal
  added = 3,      // only in B: none of its instructions corresponds
  removed = 4,    // only in A
};

struct Correlation {
  // Per instruction of A (B): the corresponding instruction of B (A), or -1.
  std::vector<std::int32_t> insn_a, insn_b;
  std::vector<InsnStatus> status_a, status_b;
  // Per block: the corresponding block on the other side (one to one), or -1.
  std::vector<std::int32_t> block_a, block_b;
  std::vector<BlockStatus> block_status_a, block_status_b;
  // The two listings aligned: (A instruction, B instruction), -1 for a gap.
  // Corresponding instructions share a line unless they moved (out of
  // order), when each has a line of its own.
  std::vector<std::pair<std::int32_t, std::int32_t>> lines;
  std::vector<bool> moved_a, moved_b;
  std::uint32_t equal = 0, changed = 0, inserted = 0, deleted = 0;

  void encode(facts::Encoder &e) const;
  static Correlation decode(facts::Decoder &d);
  friend bool operator==(const Correlation &, const Correlation &) = default;

  // Indexes of lines where a difference (a run of lines not both EQUAL) starts.
  std::vector<std::uint32_t> hunks() const;
};

Correlation correlate(const FunctionCode &a, const FunctionCode &b);

// The B function a function of A (by entry) matches, if any.
using MatchOf = std::function<std::optional<std::uint64_t>(std::uint64_t)>;

// Applies the matches to `c` (a correlate() result): EQUAL pairs whose calls
// or jumps out lead to functions that don't match each other become
// CHANGED (a target of A without a match must be the same address in B).
// Recomputes the block statuses, the lines and the counts.
void retarget(Correlation &c, const FunctionCode &a, const FunctionCode &b, const MatchOf &match_of);

// What a pair's differing instructions refer to that the other side's
// don't: calls and data references gained or lost. Only CHANGED,
// INSERTED and DELETED instructions count, and a reference both sides
// make (the same string, a call to functions that match, the same address)
// cancels out, so code that only moved shows nothing.
struct RefChange {
  bool in_b = false;  // gained (B's), else lost (A's)
  CodeRef ref;
  std::uint32_t insn = 0;  // the instruction on its side
};
std::vector<RefChange> reference_diff(const Correlation &c, const FunctionCode &a, const FunctionCode &b,
                                      const MatchOf &match_of);

// diff.correlation(A, entry_a, B, entry_b): correlate() of the two
// functions' diff.code, memoized; recomputed only when either changes.
struct CorrelationKey {
  std::string program_a, program_b;
  std::uint64_t a = 0, b = 0;

  void encode(facts::Encoder &e) const;
  static CorrelationKey decode(facts::Decoder &d);
  friend auto operator<=>(const CorrelationKey &, const CorrelationKey &) = default;
};

struct Correlate {
  static constexpr std::string_view name = "diff.correlation";
  static constexpr std::uint32_t version = 1;
  using Key = CorrelationKey;
  using Value = Correlation;
  static Value compute(facts::QueryContext &ctx, const Key &key);
  static std::string describe(const Key &k);
  static std::size_t weight(const Value &v) {
    return sizeof(Value) + (v.insn_a.capacity() + v.insn_b.capacity()) * 6 + v.lines.capacity() * 8 +
           (v.block_a.capacity() + v.block_b.capacity()) * 5;
  }
};

}  // namespace revkit::diff
