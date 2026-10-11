// A language's SLEIGH engine for tools that read its tables and decode
// bytes they own under an explicit context: the assembler (src/asm) builds
// its grammar from the engine's constructors and checks every candidate
// encoding by decoding it here, as Ghidra's assembler re-parses its
// candidates with the disassembler.
//
// Unlike Lifter, a SleighDecoder has no image and no context database to
// paint: each decode names its bytes and its context words, so changing
// context costs nothing (a Lifter rebuilds its engine). One thread at a
// time.
#pragma once

#include "revkit/lift/lifter.hh"

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace ghidra {
class SleighBase;
class Constructor;
}  // namespace ghidra

namespace revkit::lift {

// A context variable's place in the context words (SLEIGH's ContextBitRange).
struct ContextVariable {
  std::string name;
  int word = 0;
  int shift = 0;            // right shift that unpacks the value from its word
  std::uint32_t mask = 0;   // mask applied after the shift
};

// What Ghidra's Function ID hashes read from one instruction
// (MessageDigestFidHasher, docs/fid.md): the masks Ghidra's Java
// disassembler reports (InstructionPrototype.getInstructionMask and
// getOperandValueMask, computed as SleighDebugLogger computes them, quirks
// included), each displayed operand's objects (Instruction.getOpObjects)
// and type, and whether the instruction's flow is a call.
struct FidObject {
  enum class Kind : std::uint8_t { scalar, reg, address };
  Kind kind = Kind::scalar;
  std::int64_t value = 0;  // scalar: Scalar.getSignedValue(); reg: Register.getOffset()
  std::uint8_t bits = 0;   // scalar: Scalar.bitLength()
};

struct FidOperand {
  std::vector<std::uint8_t> mask;  // the operand's value bits, one byte per instruction byte
  std::vector<FidObject> objects;
  bool scalar = false;   // OperandType.SCALAR: the operand is a constant
  bool address = false;  // OperandType.ADDRESS from the operand itself (a code or memory address)
};

struct FidInstruction {
  std::uint32_t length = 0;
  bool call = false;  // FlowType.isCall()
  // False when the masks couldn't be computed (Java's prototype then has
  // none, and the hash reads the instruction as 0xa5 bytes).
  bool masks = false;
  std::vector<std::uint8_t> mask;    // identifying bits, the operands' value bits cleared
  std::vector<FidOperand> operands;  // in display order
};

class SleighDecoder {
 public:
  // `language` is a Ghidra language id (a trailing ":compiler" is ignored).
  // Throws LiftError for an unknown language.
  explicit SleighDecoder(const std::string &language);
  ~SleighDecoder();
  SleighDecoder(const SleighDecoder &) = delete;
  SleighDecoder &operator=(const SleighDecoder &) = delete;

  const std::string &language() const;
  // The engine, for reading its symbol table (read only; don't decode with it).
  const ghidra::SleighBase &sleigh() const;

  bool big_endian() const;
  unsigned alignment() const;
  // The default code space: bytes per address unit and bytes in an offset.
  unsigned word_size() const;
  unsigned address_size() const;

  // The language's default context (its .pspec's <context_data>), one word
  // per 32 context bits.
  const std::vector<std::uint32_t> &default_context() const;
  std::vector<ContextVariable> context_variables() const;
  std::optional<ContextVariable> context_variable(const std::string &name) const;
  // Sets / reads one variable in `words`. False / nullopt for an unknown name.
  bool set_context(std::vector<std::uint32_t> &words, const std::string &name, std::uint32_t value) const;
  std::optional<std::uint32_t> get_context(std::span<const std::uint32_t> words, const std::string &name) const;

  struct Decoded {
    Instruction insn;  // text and tokens as Lifter prints them (no p-code)
    // The constructors of the parse tree in walk order (pre-order, operands
    // in index order): what Ghidra's assembler compares as the construct
    // state tree.
    std::vector<const ghidra::Constructor *> tree;
  };
  // Decodes `bytes` (the bytes at `address` onwards; anything past them
  // reads as zero) under `context`. Context commits are not applied.
  // nullopt if they don't decode.
  std::optional<Decoded> decode(std::uint64_t address, std::span<const std::byte> bytes,
                                std::span<const std::uint32_t> context, bool in_delay_slot = false);

  // What Function ID hashes of the instruction at `address` (see
  // FidInstruction), decoded as decode() does; nullopt if it doesn't decode.
  std::optional<FidInstruction> fid(std::uint64_t address, std::span<const std::byte> bytes,
                                    std::span<const std::uint32_t> context);

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace revkit::lift
