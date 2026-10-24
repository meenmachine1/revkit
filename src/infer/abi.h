// Argument positions of the calling conventions inference knows, so that
// parameters seen in different places (a function's own decompilation, its
// call sites) line up and are ordered as C declares them.
#pragma once

#include "revkit/infer/decompiler.h"

#include <optional>
#include <string>
#include <vector>

namespace revkit::infer {

// Argument position of a parameter's storage: class 0 integer, 1 float,
// 2 stack; index within the class.
struct ArgPos {
  int cls = 0;
  int index = 0;
  friend auto operator<=>(const ArgPos &, const ArgPos &) = default;
};

struct Abi {
  std::vector<std::string> int_regs;    // canonical names, in argument order
  std::vector<std::string> float_regs;
  bool positional = false;   // Windows x64: the n-th argument uses the n-th slot of either class
  std::int64_t stack_base = 0;  // stack offset of the first stack argument at entry
  std::uint8_t stack_slot = 8;
  std::string int_ret;       // RAX, x0, a0
  std::string float_ret;     // XMM0, q0, fa0
  // x86-64 System V: a variadic call passes the number of vector registers
  // used in AL.
  bool al_varargs = false;
  // Other names the decompiler gives an argument register (Slot::reg is
  // the name of the widest register starting there: ARM's s0 shows as q0,
  // s2 as d1; MIPS's f12 as the pair f12_13), and the return's.
  std::vector<std::pair<std::string, ArgPos>> aliases;
  std::vector<std::string> float_ret_aliases;
};

// The convention for a language ("x86:LE:64:default") and image format;
// null for languages inference has no table for.
const Abi *abi_for(const std::string &language, bool pe);

// Nullopt if the storage isn't an argument slot.
std::optional<ArgPos> arg_position(const Abi &abi, const Slot &s);

// Whether a register is the convention's float return register.
bool float_return(const Abi &abi, const std::string &reg);

// The position of an integer-class argument among the parameters as
// declared, for the slots that hold integers and pointers: its integer
// register's index, and a stack argument's after all of them (the
// 32-bit conventions pass the fifth integer on, on the stack). Nullopt
// for a float register or anything else.
std::optional<std::size_t> int_index(const Abi &abi, const Slot &s);

// Sort key giving C declaration order: integer arguments, then floats
// (System V can't say how they interleave), then the stack. Positional
// conventions interleave by slot.
int order_key(const Abi &abi, const ArgPos &p);

}  // namespace revkit::infer
