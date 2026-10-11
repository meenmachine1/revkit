// Instruction text exactly as Ghidra's Java API prints it
// (Instruction.toString()), rebuilt from the C++ SLEIGH parse tree.
//
// The C++ engine's printAssembly() differs from Java in small ways that
// matter for diffing: Java strips spaces after commas between top-level
// operands, zero-pads address operands to 8 digits, and names registers in
// spaces with mapped registers (e.g. RISC-V CSRs). This is a port of the
// Java logic (SleighInstructionPrototype.getOpRepresentationList,
// Constructor.printList/printSeparator, HandleTpl.fixPrintPiece, Scalar and
// GenericAddress formatting) over the public C++ SLEIGH API.
#pragma once

#include "revkit/lift/lifter.hh"
#include "revkit/lift/sleigh_decoder.hh"

#include "sleigh.hh"

#include <map>
#include <string>
#include <tuple>
#include <vector>

namespace revkit::lift::detail {

class GhidraText {
 public:
  explicit GhidraText(const ghidra::Translate &trans);

  // Typed tokens for a parse tree whose handles are resolved (p-code
  // state). Their concatenated texts are Java's text.
  std::vector<Token> tokens(const ghidra::ParserContext &context, const std::string &mnemonic);
  // The concatenation of tokens().
  std::string text(const ghidra::ParserContext &context, const std::string &mnemonic);
  // What Function ID hashes of the instruction (fid_insn.cc). The context's
  // context words are reloaded and its constructors' context changes
  // replayed, as the resolve that built it made them.
  void fid(ghidra::ParserContext &context, FidInstruction &out);

 private:
  struct Piece {
    bool operand = false;
    int index = 0;     // operand index when `operand`
    std::string text;  // literal text otherwise
  };
  struct ConstructorInfo {
    std::vector<Piece> pieces;
    int first_whitespace = -1;
    int flowthru = -1;
  };
  struct Item {
    bool is_char = false;
    char c = 0;
    ghidra::FixedHandle handle{};
    bool fixable = true;
  };
  // Exposes the current node's length, which Java's ParserWalker provides.
  class Walker : public ghidra::ParserWalker {
   public:
    using ghidra::ParserWalker::ParserWalker;
    int current_length() const { return point->length; }
  };

  const ConstructorInfo &info(const ghidra::Constructor *ct);
  void constructor_list(Walker &walker, std::vector<Item> &list);
  void operand_list(Walker &walker, const ghidra::OperandSymbol *sym, std::vector<Item> &list);
  void render(const std::vector<Item> &list, int operand, std::vector<Token> &out) const;
  bool render_handle(const ghidra::FixedHandle &h, Token &out) const;
  // Literal text as separator/whitespace tokens; a word naming a register
  // becomes a register token.
  void literal(const std::string &text, int operand, std::vector<Token> &out) const;
  Varnode register_varnode(const ghidra::AddrSpace *space, std::uint64_t offset, std::uint32_t size) const;
  const std::string *find_register(const ghidra::AddrSpace *space, std::uint64_t offset, std::uint32_t size) const;
  std::string separator(const ConstructorInfo &ci, int index, int num_operands) const;
  // fid_insn.cc
  struct FidMasks;
  void fid_replay(ghidra::ParserWalkerChange &walker, FidMasks &m, std::vector<std::uint8_t> &group, bool root);
  void fid_operand_mask(const ghidra::ConstructState *state, const ghidra::OperandSymbol *sym,
                        std::vector<std::uint8_t> &mask, int depth);
  void fid_pattern_mask(const ghidra::ConstructState *state, const ghidra::PatternExpression *pe, std::uint32_t offset,
                        std::vector<std::uint8_t> &mask, int depth);
  bool fid_object(const ghidra::FixedHandle &h, FidObject &out) const;

  const ghidra::Translate &trans_;
  std::map<const ghidra::Constructor *, ConstructorInfo> infos_;
  // (space, offset, size) -> register name, built like Java's RegisterManager.
  std::map<std::tuple<const ghidra::AddrSpace *, std::uint64_t, std::uint32_t>, std::string> registers_;
  std::map<const ghidra::AddrSpace *, bool> has_registers_;
  std::map<std::string, ghidra::VarnodeData> by_name_;
};

}  // namespace revkit::lift::detail
