// SLEIGH lifting: decode instructions from a loaded image and emit raw p-code,
// using Ghidra's C++ SLEIGH engine and the specs from a Ghidra install.
#pragma once

#include "revkit/loader/image.hh"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <mutex>
#include <shared_mutex>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace revkit::lift {

class LiftError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

// Points the SLEIGH machinery at a Ghidra install (scans its .ldefs). Must be
// called before any Lifter or ImageArchitecture is built. Repeat calls with
// the same root are no-ops; a different root throws LiftError.
void initialize(const std::filesystem::path &ghidra_root);
// The Ghidra install initialize() was given, if it was called.
std::optional<std::filesystem::path> ghidra_root();

// Ghidra keeps some state in globals: its XML and p-code snippet parsers,
// the language list, and the C printer's operator tables (rewritten every
// time a printer is built). Whatever builds SLEIGH engines, Architectures or
// printers holds this lock exclusively (Lifter and
// ImageArchitecture::init_image take it themselves; construct an
// ImageArchitecture under it); whatever prints decompiled code holds it
// shared, or exclusively when printing through Ghidra's EmitPrettyPrint,
// which numbers tokens from a static counter. Decoding and decompiling
// otherwise touch only per-instance state.
std::unique_lock<std::shared_mutex> lock_ghidra_globals();
std::shared_lock<std::shared_mutex> share_ghidra_globals();

// SLEIGH engines alive (in Lifters, attached or not) and spare (parked,
// held for reuse by language: at most two per language).
struct EngineStats {
  std::size_t live = 0;
  std::size_t spare = 0;
};
EngineStats engine_stats();
// Frees the spare engines (after a big job, before returning memory to the system).
void trim_spare_engines();

// True if `language` ("proc:endian:size:variant", optionally ":compiler")
// names a language in the install, and the compiler spec if one is given.
bool language_exists(const std::string &language);

// A language the install defines (one <language> of the processors' .ldefs).
struct LanguageSummary {
  std::string id;  // "ARM:LE:32:v4t"
  std::string processor;
  bool big_endian = false;
  int size = 0;  // address size in bits
  std::string variant;
  std::string description;
  bool deprecated = false;
  std::vector<std::string> compilers;  // compiler spec ids, the default first
};

// Every language in the install, sorted by id.
std::vector<LanguageSummary> list_languages();

// A symbol the language's processor spec defines (<default_symbols> in its
// .pspec): ARM's exception vectors, AVR's I/O registers. Ghidra's loaders
// label these ("Apply Processor Defined Labels"), and an `entry` one is an
// entry point, so it becomes a function.
struct ProcessorSymbol {
  std::string name;
  std::string space;  // empty: the default space
  std::uint64_t address = 0;
  bool entry = false;
  // type="code_ptr": the address holds a pointer to the code (Cortex-M's
  // and MSP430's vectors), not the code itself.
  bool code_ptr = false;
  friend bool operator==(const ProcessorSymbol &, const ProcessorSymbol &) = default;
};
// The directory of the language's processor module in the Ghidra install
// (Ghidra/Processors/<proc>/data), where its languages/ and patterns/ are;
// nullopt for an unknown language.
std::optional<std::filesystem::path> processor_data_dir(const std::string &language);

// The language's processor symbols, in spec order; empty for an unknown
// language. Throws LiftError if the .pspec can't be read.
std::vector<ProcessorSymbol> processor_symbols(const std::string &language);

// A range the processor spec declares volatile (<volatile>: I/O registers
// of small processors), inclusive.
struct VolatileRange {
  std::string space;
  std::uint64_t first = 0, last = 0;
  friend bool operator==(const VolatileRange &, const VolatileRange &) = default;
};
// The language's volatile ranges, in spec order; empty for an unknown
// language or none. Throws LiftError if the .pspec can't be read.
std::vector<VolatileRange> processor_volatile_ranges(const std::string &language);

struct Varnode {
  std::string space;  // SLEIGH space name: ram, register, unique, const, ...
  std::uint64_t offset = 0;
  std::uint32_t size = 0;
  // LOAD/STORE input 0 names an address space rather than holding a value.
  // Then `space` is "space", offset is 0, size is the template's, and this
  // is the name. Constant offsets are masked to `size`.
  std::string referenced_space;

  friend bool operator==(const Varnode &, const Varnode &) = default;
};

struct PcodeOp {
  std::string opcode;  // Ghidra's name, e.g. "INT_ADD"
  std::optional<Varnode> output;
  std::vector<Varnode> inputs;
};

// One piece of an instruction's display text, typed from the SLEIGH parse
// tree rather than re-parsed from the string.
struct Token {
  enum class Kind : std::uint8_t {
    mnemonic,
    reg,         // a register; `reg` is its varnode
    scalar,      // an immediate or displacement; `value` holds it
    address,     // an address in a code/data space; `value` is the offset
    separator,   // brackets, commas, "+", size keywords ("dword ptr")
    whitespace,
  };
  Kind kind = Kind::separator;
  std::string text;
  // Operand position in print order; -1 for the mnemonic and for the text
  // between operands.
  int operand = -1;
  // scalar: the value as printed (sign-extended when printed negative);
  // address: the offset.
  std::uint64_t value = 0;
  // scalar: its width in bits (Ghidra's Scalar.bitLength()).
  std::uint8_t bits = 0;
  Varnode reg;

  friend bool operator==(const Token &, const Token &) = default;
};

struct Instruction {
  std::uint64_t address = 0;
  std::uint32_t length = 0;      // bytes of this instruction alone
  std::uint32_t delay_slot = 0;  // bytes of delay-slot instructions folded into `pcode`
  std::string mnemonic;
  std::string text;  // mnemonic plus operands, as SLEIGH prints them
  // `text` split into typed pieces; their texts concatenate to `text`. Empty
  // when the parse tree couldn't be walked (`text` is then the C++ engine's
  // own rendering).
  std::vector<Token> tokens;
  std::vector<PcodeOp> pcode;
  bool unimplemented = false;  // decoded, but the spec has no semantics for it
};

// Where an instruction ends: its own length and the bytes of delay-slot
// instructions after it (what Instruction::length and delay_slot hold).
struct InstructionExtent {
  std::uint32_t length = 0;
  std::uint32_t delay_slot = 0;
};

// A register the language defines: its name and storage.
struct RegisterDef {
  std::string name;
  std::uint64_t offset = 0;  // in `space`
  std::uint32_t size = 0;
  // "register", or a memory space a processor maps its registers into
  // (AVR's R0-R31 are mem:0x00-0x1f; the 8051's SFRs).
  std::string space = "register";
};

// An address space of the language, as SLEIGH defines it.
struct SpaceDef {
  enum class Kind : std::uint8_t { constant, processor, unique, other };
  std::string name;
  Kind kind = Kind::other;
  std::uint32_t address_size = 0;  // bytes in an offset (the space's size)
  std::uint32_t wordsize = 1;      // bytes per addressable unit
  bool big_endian = false;
  bool is_register = false;  // the "register" space
  bool is_default = false;   // the default code/data space
};

// An inclusive [first, last] byte range.
using AddressRange = std::pair<std::uint64_t, std::uint64_t>;

class Lifter {
 public:
  // `language` is a Ghidra language id; a trailing ":compiler" is accepted
  // and ignored, since raw p-code doesn't depend on the compiler spec.
  Lifter(std::shared_ptr<const loader::Image> image, const std::string &language);
  ~Lifter();
  Lifter(const Lifter &) = delete;
  Lifter &operator=(const Lifter &) = delete;

  // True if the language has this context variable (ARM v4 and v5 have no
  // "TMode": they have no Thumb).
  bool has_context(const std::string &name) const;

  // Paint a context variable (e.g. ARM "TMode") over [start, end), or to
  // the top of the space when `end` is unset. Layered over the language's
  // defaults from its .pspec. May be called at any time; the engine is
  // rebuilt lazily so later decodes see the change. Throws LiftError for an
  // unknown variable.
  void set_context(const std::string &name, std::uint32_t value, std::uint64_t start,
                   std::optional<std::uint64_t> end = std::nullopt);

  // A context variable's value at an address: the language's (its
  // .pspec's) under what set_context painted. Throws LiftError for an
  // unknown variable.
  std::uint32_t context_at(const std::string &name, std::uint64_t address);

  // Decode one instruction. nullopt if the bytes don't decode or are unmapped.
  // An instruction decoded as another's delay slot gets Ghidra's "_"
  // mnemonic prefix.
  std::optional<Instruction> lift(std::uint64_t address, bool in_delay_slot = false);

  // Decode one instruction from `bytes`, the bytes at `address` onwards
  // (with delay slots, enough for those too), instead of the image's.
  // Nothing outside `bytes` is read: it reads as zero, as unmapped memory
  // does, so a short span acts like the end of a segment. For callers that
  // own the bytes, such as queries reading them from the fact store.
  // The instruction's context commits (SLEIGH globalset) are not applied,
  // so the result depends on nothing decoded before.
  std::optional<Instruction> lift(std::uint64_t address, std::span<const std::byte> bytes,
                                  bool in_delay_slot = false);

  // lift(address, bytes, in_delay_slot) without the display text: no
  // mnemonic, text or tokens, for callers that only need lengths and p-code.
  // Cheaper by about the cost of printing.
  std::optional<Instruction> lift_pcode(std::uint64_t address, std::span<const std::byte> bytes,
                                        bool in_delay_slot = false);
  // lift(address, in_delay_slot) without the display text.
  std::optional<Instruction> lift_pcode(std::uint64_t address, bool in_delay_slot = false);
  // lift_pcode(address, bytes, in_delay_slot) with the mnemonic (no text or
  // tokens): what an instruction is, for a census of instruction forms,
  // without the cost of printing its operands.
  std::optional<Instruction> lift_mnemonic(std::uint64_t address, std::span<const std::byte> bytes,
                                           bool in_delay_slot = false);

  // The extent lift(address, in_delay_slot) would report, and nullopt
  // exactly when it would, without printing operands or emitting p-code
  // (except for instructions with delay slots). Has the same effect on the
  // engine's context as lift(): the instruction's context commits apply.
  std::optional<InstructionExtent> measure(std::uint64_t address, bool in_delay_slot = false);

  // True if decoded instructions changed the context (SLEIGH `globalset`
  // commits, e.g. ARM/Thumb switches at branch targets) since the engine was
  // last built. While false, a decode depends only on the bytes and the
  // context set with set_context(), not on what was decoded before, so
  // separate Lifters over one image give identical results.
  bool context_changed() const;

  // Lets the SLEIGH engine go while the Lifter is idle (docs/memory.md
  // "SLEIGH engines"): it joins the spares of its language, which any
  // Lifter of the language (another program's too) takes rather than decode
  // the .sla again; the next decode here takes a spare or builds one. False
  // (and nothing done) when decoding has committed context (ARM/Thumb
  // switches) that a rebuild would lose. Not while another thread uses it.
  bool park();
  bool parked() const;

  // Linear sweep over [start, end). Undecodable spots are skipped by the
  // instruction alignment. Delay-slot instructions are marked.
  std::vector<Instruction> lift_range(std::uint64_t start, std::uint64_t end);

  // Follow control flow from `entry` (branches, fall-through; calls are not
  // followed) within the executable region containing it. Returns the merged
  // body ranges, sorted. Empty if `entry` isn't executable.
  std::vector<AddressRange> flow_body(std::uint64_t entry, std::size_t max_instructions = 100000);

  // Name of the register at (offset, size) in the register space, or "" if
  // no register is exactly that varnode.
  std::string register_name(std::uint64_t offset, std::uint32_t size);
  // The varnode of a register by name, if the language has one.
  std::optional<Varnode> register_varnode(const std::string &name);

  // Every register the language names: those in the register space
  // first, then by space; by (offset, size larger first, name) in each.
  std::vector<RegisterDef> registers();
  // The language's user-defined p-code ops (CALLOTHER's input 0 indexes it).
  std::vector<std::string> userops();
  // The language's address spaces, in SLEIGH's order (index = space index).
  std::vector<SpaceDef> spaces();
  bool big_endian();

  unsigned alignment();
  const std::string &language() const;
  std::string code_space_name();
  // The language's memory spaces (processor spaces other than "register"),
  // e.g. {"ram"}, or {"ram", "csreg"} for RISC-V. With more than one, Ghidra
  // qualifies default names with the space: FUN_ram_00101000.
  std::vector<std::string> memory_spaces();

 private:
  // What of the display text a decode prints.
  enum class Text : std::uint8_t { none, mnemonic, all };
  std::optional<Instruction> decode(std::uint64_t address, bool in_delay_slot, Text text = Text::all);
  std::optional<Instruction> lift_window(std::uint64_t address, std::span<const std::byte> bytes, bool in_delay_slot,
                                         Text text);
  void emit_pcode(Instruction &insn);

  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace revkit::lift
