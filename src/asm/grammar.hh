// The assembly grammar of a SLEIGH language, built from the constructors of
// its loaded .sla (Ghidra's AbstractSleighAssemblerBuilder): one
// nonterminal per subtable, one production per distinct display layout of
// its constructors, whose terminals are the display's literal text and its
// operands (numbers, register and name tables, value maps).
//
// Also holds what resolution needs about each constructor, converted out of
// SLEIGH's objects: patterns as Blocks, operands with their offsets and
// defining expressions, context operations, all as plain data.
#pragma once

#include "block.hh"

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace ghidra {
class SleighBase;
class Constructor;
}  // namespace ghidra

namespace revkit::lift {
class SleighDecoder;
}

namespace revkit::assembler::detail {

// A pattern expression (SLEIGH's PatternExpression tree), hash-consed: equal
// expressions have equal indices into Grammar::exprs.
struct Expr {
  enum Op : std::uint8_t {
    Const, Token, Context, Operand, Start, End, Next2,
    Plus, Sub, Mult, Shl, Shr, And, Or, Xor, Div, Neg, Not,
  };
  Op op = Const;
  std::int64_t value = 0;  // Const
  // Token: fields as TokenField has them; Context: start/end bit and byte, shift.
  bool big_endian = false, sign = false;
  int bit_start = 0, bit_end = 0, byte_start = 0, byte_end = 0, shift = 0;
  int cons = -1, index = -1;  // Operand: constructor and operand index
  int l = -1, r = -1;         // children

  friend bool operator==(const Expr &, const Expr &) = default;
};

struct Operand {
  enum Kind : std::uint8_t {
    Subtable,   // nt
    Value,      // a number: expr is the value printed
    Registers,  // a VarnodeList: expr selects the entry
    Names,      // a NameSymbol: expr selects the entry
    Values,     // a ValueMap: expr selects the entry
    Fixed,      // a VarnodeSymbol: nothing to solve
    Other,
  };
  Kind kind = Other;
  int nt = -1;
  int expr = -1;
  int offset_base = -1;  // operand whose end this one is relative to; -1: the constructor's start
  int rel_offset = 0;
  int min_length = 0;
  std::string name;
};

struct ContextOp {
  int expr = -1;
  int word = 0;
  std::uint32_t mask = 0;
  int shift = 0;
};

struct Pattern {
  Block ins, ctx;
};

struct Constructor {
  const ghidra::Constructor *ct = nullptr;
  int nt = -1;
  int min_length = 0;
  int line = 0;
  std::vector<Operand> ops;
  std::vector<ContextOp> ctx_ops;
  std::vector<Pattern> patterns;  // the disjoint patterns that select it
  // Bits written by ctx_ops, as a context Block mask (value unused).
  Block writes;
};

struct Terminal {
  enum Kind : std::uint8_t {
    Literal,   // text (lower case); never whitespace
    Space,     // whitespace, possibly empty (not between two word characters)
    Number,    // a number or label; bits: the operand's printed size (0: any)
    Names,     // one of names (lower case) -> entry indices
    Values,    // a number in values -> entry indices
    Register,  // a fixed register name (text), taking an operand slot
  };
  Kind kind = Literal;
  std::string text;
  int bits = 0;
  bool address = false;
  std::vector<std::pair<std::string, std::vector<int>>> names;  // longest first
  std::map<std::int64_t, std::vector<int>> values;
  // Number: names that stand for values (registers mapped in the operand's
  // space, as RISC-V's CSRs print), lower case.
  std::vector<std::pair<std::string, std::int64_t>> named;
  std::string key;  // identity, for interning
  bool takes_operand() const { return kind != Literal && kind != Space; }
  // What to show for completion: the literal, the register, or a placeholder.
  std::vector<std::string> suggestions() const;
};

struct Sym {
  bool nt = false;
  int id = -1;
};

struct Production {
  int lhs = -1;
  std::vector<Sym> rhs;
  // Constructors with this layout, and for each the operand index of every
  // operand-taking symbol of rhs, in rhs order.
  std::vector<int> cons;
  std::vector<std::vector<int>> operand_index;
  bool pure_recursion = false;  // lhs -> lhs: Ghidra's root recursion (x86 prefixes)
};

struct Grammar {
  std::string language;
  bool big_endian = false;
  unsigned alignment = 1;
  unsigned word_size = 1;
  unsigned address_size = 4;
  int context_words = 0;

  std::vector<std::string> nt_names;
  std::vector<std::vector<int>> nt_productions;  // productions of each nonterminal
  std::vector<std::vector<int>> nt_cons;         // constructors of each nonterminal
  std::vector<bool> nt_nullable;
  int start = -1;
  std::vector<Production> productions;
  std::vector<Terminal> terminals;
  std::vector<Constructor> cons;
  std::vector<Expr> exprs;
  std::unordered_map<std::string, int> expr_ids;
  std::unordered_map<const ghidra::Constructor *, int> cons_index;
  // Root recursion (x86 prefixes): constructors of `start` whose only
  // printed piece is `start`, and the context bits any of them writes.
  std::vector<int> recursive_cons;
  Block recursion_writes;

  int add_expr(const Expr &e);
  std::string describe(int cons) const;
  std::string describe_production(int prod) const;
};

// Builds the grammar from the decoder's engine. Throws std::runtime_error
// for constructs it can't represent.
std::shared_ptr<const Grammar> build_grammar(const lift::SleighDecoder &decoder);

}  // namespace revkit::assembler::detail
