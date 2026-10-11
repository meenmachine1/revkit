// Call-stack unwinding (docs/debugger.md, "Call stack"): from a stop's
// registers and memory, the frames above it. Each frame is unwound with
// the program's call-frame information (.eh_frame, .debug_frame) where it
// covers the pc; else by the frame-pointer chain; else by scanning the
// stack for a return address (a code address just after a call).
#pragma once

#include "revkit/loader/image.hh"

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::debug {

// An architecture's registers as DWARF numbers them, by SLEIGH name.
struct UnwindArch {
  // index: DWARF register number; "" where unknown.
  std::vector<std::string> names;
  int sp = -1, fp = -1;   // DWARF numbers of the stack and frame pointers
  int ra = -1;            // the return-address column CFI uses by default
  int lr = -1;            // a link register holding a leaf's return address (-1: none)
  std::string pc_name;    // the program counter (no DWARF number on some)
  unsigned address_size = 8;
  bool big_endian = false;
  // The frame-record layout: [fp + prev_fp_at] = caller's fp, [fp + ra_at]
  // = return address, caller's sp = fp + cfa_at.
  std::int64_t prev_fp_at = 0, ra_at = 8, cfa_at = 16;
  std::uint32_t insn_align = 1;  // 4 on fixed-width ISAs: return addresses are aligned

  // For a SLEIGH language id ("x86:LE:64:default", "AARCH64:LE:64:v8A",
  // "ARM:LE:32:v7", "RISCV:LE:64:RV64GC", "x86:LE:32:default"); nullopt
  // for others.
  static std::optional<UnwindArch> for_language(std::string_view language);
};

// One rule of a CFI row: how to find a register's value in the caller.
struct CfiRule {
  enum class Kind : std::uint8_t { undefined, same, offset, val_offset, reg, expression };
  Kind kind = Kind::same;
  std::int64_t n = 0;  // offset from the CFA, or the register for `reg`
};

// The unwind rules at one pc.
struct CfiRow {
  int cfa_reg = -1;
  std::int64_t cfa_offset = 0;
  bool cfa_expression = false;  // DW_CFA_def_cfa_expression: not evaluated
  int ra = -1;                  // the CIE's return-address column
  std::map<int, CfiRule> rules;
};

// The call-frame information of one image, by static address.
class CfiTable {
 public:
  // Every FDE of `image`'s .eh_frame and .debug_frame. Empty without them;
  // malformed records end the section's walk (what came before stays).
  static std::shared_ptr<const CfiTable> from_image(const loader::Image &image);
  // From one section's bytes, loaded at `address` (static), `eh` for
  // .eh_frame's encoding; `delta` moves absolute addresses (a rebased image).
  void add_section(std::span<const std::uint8_t> bytes, std::uint64_t address, bool eh, unsigned address_size,
                   bool big_endian, std::int64_t delta);

  // The rules at a static pc, if an FDE covers it.
  std::optional<CfiRow> row_at(std::uint64_t pc) const;
  std::size_t size() const { return fdes_.size(); }

 private:
  struct Cie {
    std::uint64_t code_align = 1;
    std::int64_t data_align = 1;
    int ra = -1;
    std::uint8_t fde_enc = 0;
    bool has_z = false;  // FDEs carry augmentation data
    std::vector<std::uint8_t> instructions;
  };
  struct Fde {
    std::uint64_t start = 0, end = 0;
    std::shared_ptr<const Cie> cie;
    std::vector<std::uint8_t> instructions;
    unsigned address_size = 8;
    bool big_endian = false;
  };
  std::vector<Fde> fdes_;  // sorted by start
};

struct FrameRegister {
  std::string name;
  std::uint64_t value = 0;
};

struct Frame {
  // The frame's pc: the stop's for frame 0, the return address for callers.
  std::uint64_t pc = 0;
  std::uint64_t sp = 0;   // its stack pointer
  std::uint64_t cfa = 0;  // its canonical frame address, 0 when not known
  // How the frame was found: "registers" (frame 0), "cfi", "entry" (frame
  // 0 at a function's first instruction), "frame pointer", "link register",
  // "stack scan".
  std::string how;
  // The registers known in this frame (pc, sp, fp and those the unwind
  // restored), by SLEIGH name.
  std::vector<FrameRegister> registers;
};

// What unwinding reads, at one stop or snapshot. Addresses are runtime.
struct UnwindSource {
  std::function<std::optional<std::uint64_t>(const std::string &name)> reg;
  std::function<std::optional<std::uint64_t>(std::uint64_t address, unsigned size)> read;
  std::function<bool(std::uint64_t address)> is_code;
  // The CFI rules at a runtime pc, when the program's information covers it.
  std::function<std::optional<CfiRow>(std::uint64_t pc)> cfi;
  // A return address: the instruction before it is a call. Unset: any code address.
  std::function<bool(std::uint64_t address)> after_call;
  // The pc is a function's first instruction (its frame not set up yet: the
  // return address is at the stack pointer, or in the link register).
  std::function<bool(std::uint64_t pc)> at_entry;
};

std::vector<Frame> unwind(const UnwindArch &arch, const UnwindSource &source, std::size_t max_frames = 64);

}  // namespace revkit::debug
