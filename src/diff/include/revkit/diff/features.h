// Per-function fingerprints for binary diffing (docs/diff.md; design in
// docs/diff/design.md, section 1), as fact-engine queries keyed like
// function discovery's (analysis::Location: a program and an entry).
//
//   F0  name       the function's name when it has a non-default one: an
//                  asserted name (user, debug info, a port), a symbol or
//                  export, or the import a stub jumps to
//   F1  bytes      the instructions' bytes with every field that encodes an
//                  address outside the function masked (whole instructions
//                  where the field isn't byte-aligned), with the
//                  instructions' offsets from the entry: equal for the same
//                  code moved elsewhere
//   F2  pcode      the raw p-code: opcodes, operand kinds (const, register,
//                  unique, memory) and sizes, constant values except
//                  addresses; never register numbers or addresses
//   F3  shape      the control-flow graph's BinDiff MD index, block, edge
//                  and loop counts; and `opcodes`, an order-free signature
//                  of the p-code opcodes (a product of primes) with the
//                  instruction count
//   F4  refs       a bag of what the function refers to that survives a
//                  rebuild: imports it calls, named functions it calls,
//                  strings it reads, large constants
//
// Calls (internal callees in call-site order), strings and globals in
// reference order are kept beside the hashes for the matcher's
// neighbourhoods. Imports and strings are folded into F1 and F2 as well, so
// code that differs only in which import or which kind of datum it touches
// doesn't hash equal.
//
// Every value is a pure function of what the query reads: the program's
// ProgramInfo, the function (analysis.function) and its flow
// (analysis.flow), the bytes it decodes and the strings it reads, the
// NAME assertion at its entry, and analysis.function of each callee. So
// an unchanged function's features validate by fingerprint after any edit
// elsewhere, and a rename re-runs only that function and its callers.
#pragma once

#include "revkit/analysis/analysis.h"
#include "revkit/facts/engine.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::diff {

// Where F0's name came from.
enum class NameSource : std::uint8_t {
  none,      // a default name (FUN_...): F0 is empty
  asserted,  // a live NAME assertion: a user, debug info, an agent, a port
  symbol,    // the file's symbol table or exports
  import,    // a stub jumping to an import, named after it
};

struct FunctionFeatures {
  std::uint64_t entry = 0;
  std::string name;  // F0; empty for a default name
  NameSource name_source = NameSource::none;
  bool thunk = false;   // analysis says it is a thunk (a stub)
  std::uint64_t bytes = 0;    // F1
  std::uint64_t raw = 0;      // the bytes as they are, unmasked: equal code at the same address
  std::uint64_t pcode = 0;    // F2
  std::uint64_t shape = 0;    // F3: MD index, blocks, edges, loops
  std::uint64_t opcodes = 0;  // F3: prime signature of the opcodes, with the instruction count
  std::uint64_t refs = 0;     // F4: hash of `bag`, 0 when it is empty
  double md_index = 0;
  std::uint32_t instructions = 0, blocks = 0, edges = 0, loops = 0, pcode_ops = 0;
  // Internal call sites in instruction order: the entries they call (calls
  // and jumps to other functions; a site per instruction and target).
  std::vector<std::uint64_t> calls;
  // F4's elements: 32-bit hashes, sorted and unique.
  std::vector<std::uint32_t> bag;
  // Strings read (content hashes) and globals referred to (addresses), each
  // in order of first reference, at most kMaxRefs.
  std::vector<std::uint32_t> strings;
  std::vector<std::uint64_t> globals;

  static constexpr std::size_t kMaxRefs = 32;

  void encode(facts::Encoder &e) const;
  static FunctionFeatures decode(facts::Decoder &d);
  friend bool operator==(const FunctionFeatures &, const FunctionFeatures &) = default;
};

// diff.features(program, entry): one function's fingerprints. A Location
// that isn't a function's entry gives features with entry 0.
struct Features {
  static constexpr std::string_view name = "diff.features";
  static constexpr std::uint32_t version = 3;  // 3: F1/F2 leave out what data references point at; raw
  using Key = analysis::Location;
  using Value = FunctionFeatures;
  static Value compute(facts::QueryContext &ctx, const Key &key);
  static std::string describe(const Key &k) { return analysis::describe(k); }
  static std::size_t weight(const Value &v) {
    return sizeof(Value) + v.name.capacity() + v.calls.capacity() * 8 + v.bag.capacity() * 4 +
           v.strings.capacity() * 4 + v.globals.capacity() * 8;
  }
};

// Whether `name` is one analysis makes up for an unnamed function
// (FUN_..., thunk_FUN_...), which F0 ignores.
bool is_default_name(std::string_view name);

// Stable 64-bit hashing for fingerprints (the same on every platform and
// in every process).
class Hasher {
 public:
  Hasher &u64(std::uint64_t v) {
    h_ ^= v * 0x9e3779b97f4a7c15ULL;
    h_ = ((h_ << 31) | (h_ >> 33)) * 0xbf58476d1ce4e5b9ULL;
    ++n_;
    return *this;
  }
  Hasher &str(std::string_view s);
  std::uint64_t done() const {
    std::uint64_t x = h_ ^ (n_ * 0x94d049bb133111ebULL);
    x ^= x >> 30;
    x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27;
    x *= 0x94d049bb133111ebULL;
    x ^= x >> 31;
    return x;
  }

 private:
  std::uint64_t h_ = 0x2545f4914f6cdd1dULL;
  std::uint64_t n_ = 0;
};

}  // namespace revkit::diff
