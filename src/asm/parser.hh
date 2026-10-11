// An Earley parser over the characters of one line of assembly, with the
// grammar's terminals matching spans themselves (numbers, register names,
// literals, optional whitespace). It yields every parse tree (Ghidra's
// LALR(1) parser forks on conflicts to the same end), and the terminals the
// grammar expects where the text stops parsing, which is what completion
// offers.
#pragma once

#include "grammar.hh"

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::assembler::detail {

// Resolves a label in an operand to an address (nullopt: unknown).
using SymbolLookup = std::function<std::optional<std::uint64_t>(std::string_view)>;

struct Token {
  int term = -1;
  int start = 0, end = 0;
  std::int64_t number = 0;                 // Number and Values: the value
  const std::vector<int> *entries = nullptr;  // Names and Values: table indices
};

struct Tree;
struct Child {
  std::shared_ptr<const Tree> sub;  // nonterminal
  Token tok;                        // terminal
};
struct Tree {
  int prod = -1;
  int start = 0, end = 0;
  std::vector<Child> kids;  // one per rhs symbol
};

struct ParseResult {
  std::vector<std::shared_ptr<const Tree>> trees;
  bool truncated = false;  // more trees than the cap
  // Where parsing stopped (the last position any parse reached) and the
  // terminals expected there. With a complete parse: the end of the text.
  int stop = 0;
  std::vector<int> expected;
};

ParseResult parse(const Grammar &g, std::string_view text, const SymbolLookup &symbols,
                  std::size_t max_trees = 4096);

// The terminals the grammar expects after `prefix` (whose last partial word,
// if any, is excluded and returned as `partial`).
struct Expectation {
  int at = 0;              // position the suggestions replace from
  std::string partial;     // text between `at` and the end of the prefix
  std::vector<int> terms;  // terminals expected at `at`
  bool ok = true;          // false: the prefix itself doesn't parse
};
Expectation expect(const Grammar &g, std::string_view prefix, const SymbolLookup &symbols);

}  // namespace revkit::assembler::detail
