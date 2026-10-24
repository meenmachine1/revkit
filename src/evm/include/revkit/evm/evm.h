// revkit::evm: Ethereum Virtual Machine bytecode (docs/evm.md). What the
// SLEIGH processor (processors/EVM) can't know from one instruction: where a
// file's runtime code is, the function dispatcher's selectors, and where
// computed jumps go, found by running the code on an abstract stack of
// constants.
//
// Offsets here are within one piece of code (a contract's runtime code or
// its creation code), as the code's own jumps and PC count them. The
// backend lays the runtime out at 0 and creation code at kCreationBase.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <vector>

namespace revkit::evm {

using Bytes = std::vector<std::byte>;

// The language revkit's processor defines (processors/EVM).
inline constexpr const char *kLanguage = "EVM:BE:32:default";
// Where the loader puts creation code: its own segment, so its jumps (which
// are offsets in it) stay apart from the runtime's (at 0). The processor adds
// a jump's segment (its address & 0xfff00000) to the target.
inline constexpr std::uint32_t kCreationBase = 0x100000;

// One instruction. `push` is the size of a PUSHn's immediate (0 otherwise);
// `value` its value when it fits in 64 bits.
struct Insn {
  std::uint32_t pc = 0;
  std::uint8_t op = 0;
  std::uint8_t push = 0;
  std::optional<std::uint64_t> value;
  std::uint32_t length() const { return 1u + push; }
};

// The mnemonic ("PUSH2", "JUMPI"; "INVALID" for an unassigned opcode).
std::string mnemonic(std::uint8_t op);
// Linear disassembly: every instruction, PUSH immediates skipped; a PUSH
// cut short by the end of the code is the last.
std::vector<Insn> disassemble(std::span<const std::byte> code);

// Whether bytes start the way solc's contracts do: the free-memory pointer
// set up first, PUSH1 0x80 PUSH1 0x40 MSTORE (6080604052), or PUSH1 0x60
// PUSH1 0x40 MSTORE before solc 0.4.22 (6060604052).
bool is_bytecode(std::span<const std::byte> bytes);
// A file's bytecode: the file itself, or the bytes its hex text spells
// ("0x6080604052..."), when that is EVM bytecode by is_bytecode; else nullopt.
std::optional<Bytes> bytecode_of(std::span<const std::byte> file);

// solc's metadata trailer: CBOR at the end of the runtime code, its length in
// the last two bytes (big-endian). Not code.
struct Metadata {
  std::uint32_t offset = 0;
  std::uint32_t size = 0;  // the CBOR and its two length bytes
};
std::optional<Metadata> metadata(std::span<const std::byte> code);

// Jumps and where they go, found by running the code from `entry` with an
// abstract stack of the constants PUSH and PC put there, moved by DUP, SWAP
// and POP (what any other instruction computes is unknown: jump targets and
// return addresses are pushed, and loop counters would make every state a
// new one), one state per distinct stack at each JUMPDEST, within a budget.
struct Analysis {
  std::vector<Insn> insns;
  std::set<std::uint32_t> jumpdests;  // JUMPDEST instructions (not in PUSH data or the metadata)
  // PUSH1..PUSH4 tag immediately before JUMP or JUMPI: one instruction in the
  // processor, a direct branch. By the PUSH's offset: the tag.
  std::map<std::uint32_t, std::uint32_t> direct;
  // The other JUMP and JUMPI instructions reached: the targets found. A
  // jump whose target wasn't a constant on some path is in `unresolved`
  // too (with whatever targets other paths gave).
  std::map<std::uint32_t, std::set<std::uint32_t>> computed;
  std::set<std::uint32_t> unresolved;
  // JUMP and JUMPI instructions (folded or not) no path reached.
  std::set<std::uint32_t> unreached;
  std::uint32_t jumps = 0;  // JUMP and JUMPI instructions outside the metadata
  bool budget = false;      // the state budget stopped it: some paths weren't followed
  // CODECOPY(dst, offset, size) and RETURN(offset, size) with constant
  // operands, for layout().
  std::vector<std::array<std::uint64_t, 3>> codecopies;
  std::vector<std::array<std::uint64_t, 2>> returns;
  std::optional<Metadata> meta;

  // Jumps whose targets are known: direct ones and computed ones resolved.
  std::uint32_t resolved() const;
};
Analysis analyze(std::span<const std::byte> code, std::uint32_t entry = 0);

// Where a file's runtime code is. Creation code (a constructor) copies the
// runtime with CODECOPY into memory and RETURNs it: a CODECOPY of constant
// offset and size followed by a RETURN of the same size gives the slice.
// Otherwise the whole file is runtime code.
struct Layout {
  bool creation = false;
  std::uint32_t runtime_offset = 0;
  std::uint32_t runtime_size = 0;
};
Layout layout(std::span<const std::byte> file);

// The function dispatcher's comparisons: PUSH4 selector, EQ (after DUP1, or
// with DUP2 between), PUSHn tag, JUMPI. One per selector, in code order.
struct Selector {
  std::uint32_t selector = 0;
  std::uint32_t entry = 0;  // the tag: the function's code
  std::uint32_t at = 0;     // the PUSH4
};
std::vector<Selector> dispatcher(const std::vector<Insn> &insns);

// A short built-in table of well-known function signatures (ERC-20,
// ERC-721, ERC-165, Ownable): what a selector's function is likely to be.
struct KnownSignature {
  std::uint32_t selector;
  const char *signature;  // "transfer(address,uint256)"
  const char *standard;   // "ERC-20"
};
std::span<const KnownSignature> known_signatures();
const KnownSignature *known_signature(std::uint32_t selector);
// "transfer" from "transfer(address,uint256)".
std::string signature_name(const char *signature);
// "func_0xa9059cbb".
std::string selector_name(std::uint32_t selector);

}  // namespace revkit::evm
