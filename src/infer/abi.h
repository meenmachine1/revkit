// Argument positions of the calling conventions inference knows, so that
// parameters seen in different places (a function's own decompilation, its
// call sites) line up and are ordered as C declares them.
#pragma once

#include "revkit/infer/decompiler.h"

#include <optional>
#include <string>
#include <vector>

namespace revkit::infer {

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
};

// The convention for a language ("x86:LE:64:default") and image format;
// null for languages inference has no table for.
const Abi *abi_for(const std::string &language, bool pe);

// Argument position of a parameter's storage: class 0 integer, 1 float,
// 2 stack; index within the class. Nullopt if it isn't an argument slot.
struct ArgPos {
  int cls = 0;
  int index = 0;
  friend auto operator<=>(const ArgPos &, const ArgPos &) = default;
};
std::optional<ArgPos> arg_position(const Abi &abi, const Slot &s);

// Sort key giving C declaration order: integer arguments, then floats
// (System V can't say how they interleave), then the stack. Positional
// conventions interleave by slot.
int order_key(const Abi &abi, const ArgPos &p);

}  // namespace revkit::infer
