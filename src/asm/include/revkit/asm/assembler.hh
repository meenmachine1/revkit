// A SLEIGH-inverting assembler: one line of assembly, in the syntax the
// listing prints, to every encoding of it at an address, for any language
// Ghidra's specs define. A C++ port of the approach of Ghidra's assembler
// (ghidra.app.plugin.assembler), over the vendored SLEIGH (docs/patching.md):
//
//   1. a grammar from each constructor's display pieces (a nonterminal per
//      subtable), built once per language;
//   2. an Earley parser over the characters, giving every parse tree and,
//      where the text stops parsing, the tokens the grammar expects
//      (completion);
//   3. resolution: each tree's constructors' patterns combined, operand
//      values solved back into instruction bits (all solutions), inst_next
//      backfilled once the length is known, context changes solved
//      backwards to the program's context at the address, and x86-style
//      prefix recursion searched by depth;
//   4. verification: every candidate is decoded with the disassembler under
//      the same context and kept only if it decodes to the same
//      constructors and the same text;
//   5. ranking: shortest first, then the encoding style of the bytes now at
//      the address: canonical if they are canonical, else fewest bits
//      changed, so a toolchain's encodings (ARM's rotated immediates)
//      survive an edit.
//
// An Assembler is used by one thread at a time; grammars are shared by all
// assemblers of a language.
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::assembler {

struct Candidate {
  std::vector<std::uint8_t> bytes;
  std::string text;          // the candidate as the disassembler prints it
  unsigned hamming = 0;      // bits that differ from the current bytes (missing bytes count 8)
  bool current = false;      // the bytes already at the address
  // The order the assembler found it in: its canonical encodings first
  // (an ARM immediate's smallest rotation, the plain form before
  // redundant prefixes).
  unsigned order = 0;
};

struct Result {
  std::vector<Candidate> candidates;  // ranked; empty on error
  std::string error;                  // why there are none
  int error_column = -1;              // where the text stopped parsing, if it didn't parse
  std::vector<std::string> expected;  // what the grammar accepts there
  bool truncated = false;             // more parses or candidates than the limits
  double micros = 0;
};

struct Completion {
  std::size_t from = 0;              // replace text[from, cursor) with an item
  std::vector<std::string> items;    // sorted; "<number>"/"<address>" for operands
  bool valid_prefix = true;          // the text before `from` parses
};

struct Options {
  std::span<const std::uint8_t> current;  // bytes now at the address: ranking and unconstrained bits
  // The instruction now at the address, as the listing prints it. When
  // the current bytes are its canonical encoding, candidates of the same
  // length rank canonical first (a toolchain that encodes canonically
  // keeps doing so); otherwise nearest to the current bytes first (a
  // toolchain's own choice, such as a non-canonical rotation, is kept).
  std::string_view current_text;
  // Labels in operands ("bl my_func"): their addresses.
  std::function<std::optional<std::uint64_t>(std::string_view)> symbols;
  std::size_t max_candidates = 16;
  int max_prefix_depth = 3;  // x86-style prefix constructors to try
};

struct GrammarStats {
  std::size_t constructors = 0, productions = 0, terminals = 0, nonterminals = 0;
  double build_ms = 0;
};

class Assembler {
 public:
  // Throws std::runtime_error (lift::LiftError) for an unknown language or
  // a spec the grammar builder can't represent. lift::initialize() first.
  explicit Assembler(const std::string &language);
  ~Assembler();
  Assembler(const Assembler &) = delete;
  Assembler &operator=(const Assembler &) = delete;

  const std::string &language() const;
  GrammarStats stats() const;

  // Context words for decoding at an address: the language's defaults, with
  // variables set by name (ARM "TMode").
  std::vector<std::uint32_t> default_context() const;
  bool set_context(std::vector<std::uint32_t> &words, const std::string &name, std::uint32_t value) const;
  std::optional<std::uint32_t> get_context(std::span<const std::uint32_t> words, const std::string &name) const;

  Result assemble(std::uint64_t address, std::string_view text, std::span<const std::uint32_t> context,
                  const Options &options = {});

  Completion complete(std::uint64_t address, std::string_view text, std::size_t cursor,
                      std::span<const std::uint32_t> context, const Options &options = {});

  // The disassembler's text and length for bytes at an address (nullopt:
  // they don't decode). What verification compares against.
  struct Disassembly {
    std::string text;
    unsigned length = 0;
    std::vector<std::string> constructors;  // "table:line" in walk order
  };
  std::optional<Disassembly> disassemble(std::uint64_t address, std::span<const std::uint8_t> bytes,
                                         std::span<const std::uint32_t> context);

  // Whether two lines say the same: case, whitespace and number spelling
  // aside (0x5f = 95, 0x000a0000 = 0xa0000).
  static bool same_text(std::string_view a, std::string_view b);

  // Every production with its constructors, for debugging specs.
  std::vector<std::string> debug_productions() const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace revkit::assembler
