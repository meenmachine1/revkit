// Solving SLEIGH pattern expressions for the instruction and context bits
// that give them a required value (Ghidra's RecursiveDescentSolver), with
// every solution rather than the first: an ARM immediate has one encoding
// per rotation, and ranking by distance to the current bytes needs them all.
#pragma once

#include "grammar.hh"

#include <optional>
#include <vector>

namespace revkit::assembler::detail {

struct Solution {
  Block ins;  // instruction bits, from the start of the instruction
  Block ctx;  // context bits read
};

// The value needs inst_next, unknown until the instruction's length is.
struct NeedsBackfill {};

struct SolveEnv {
  const Grammar &g;
  std::uint64_t inst_start = 0;               // in address units
  std::optional<std::uint64_t> inst_next;     // in address units, once known
  const Block *ins = nullptr;                 // instruction bits known so far
  const Block *ctx = nullptr;                 // context bits known here
};

// Offset of operand `index` of constructor `cons` from the constructor's
// start, with operands it is relative to at their minimum lengths
// (Ghidra's AbstractAssemblyTreeResolver.computeOffset).
int operand_offset(const Grammar &g, int cons, int index);

// Solutions to expression `e` == goal, the expression read at instruction
// offset `at` inside a constructor starting at `cons_at`. Empty: none.
// Throws NeedsBackfill.
std::vector<Solution> solve(const SolveEnv &env, int e, int at, int cons_at, const Masked &goal);

// The expression's value from what is known.
Masked evaluate(const SolveEnv &env, int e, int at, int cons_at);

// Field writers (also used for value tables).
bool write_token(const Expr &x, int at, const Masked &v, Block &ins);
Masked read_token(const Expr &x, int at, const Block *ins);
bool write_context(const Expr &x, const Masked &v, Block &ctx);
Masked read_context(const Expr &x, const Block *ctx);

}  // namespace revkit::assembler::detail
