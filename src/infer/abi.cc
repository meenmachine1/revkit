#include "abi.h"

#include "revkit/infer/infer.h"

namespace revkit::infer {

namespace {

std::vector<std::string> numbered(const std::string &prefix, int n, int first = 0) {
  std::vector<std::string> out;
  for (int i = first; i < first + n; ++i) out.push_back(prefix + std::to_string(i));
  return out;
}

bool is_32(const std::string &language) { return language.find(":32:") != std::string::npos; }

// AAPCS: r0-r3, then the stack from the entry's sp; VFP arguments (the
// hard-float variant the default .cspec models) in s0-s15, which the
// decompiler names by the widest register starting there.
Abi make_arm() {
  Abi a{{"r0", "r1", "r2", "r3"}, numbered("s", 16), false, 0, 4, "r0", "s0", false, {}, {"d0", "q0"}};
  for (int i = 0; i < 8; ++i) a.aliases.push_back({"d" + std::to_string(i), ArgPos{1, 2 * i}});
  for (int i = 0; i < 4; ++i) a.aliases.push_back({"q" + std::to_string(i), ArgPos{1, 4 * i}});
  return a;
}

// MIPS o32: a0-a3, the stack past the 16 bytes the caller reserves for
// them; floats in f12 and f14 (pairs for doubles).
Abi make_mips() {
  Abi a{{"a0", "a1", "a2", "a3"}, {"f12", "f14"}, false, 16, 4, "v0", "f0", false, {}, {"f0_1"}};
  a.aliases = {{"f12_13", ArgPos{1, 0}}, {"f14_15", ArgPos{1, 1}}};
  return a;
}

}  // namespace

const Abi *abi_for(const std::string &language, bool pe) {
  static const Abi sysv{{"RDI", "RSI", "RDX", "RCX", "R8", "R9"}, numbered("XMM", 8), false, 8, 8, "RAX", "XMM0", true};
  static const Abi win64{{"RCX", "RDX", "R8", "R9"}, numbered("XMM", 4), true, 0x28, 8, "RAX", "XMM0", false};
  static const Abi aarch64{numbered("x", 8), numbered("q", 8), false, 0, 8, "x0", "q0", false};
  static const Abi riscv{numbered("a", 8), numbered("fa", 8), false, 0, 8, "a0", "fa0", false};
  // 32-bit conventions: pointers and ints are one size, so what types a
  // value as a pointer is how it is used, never its width.
  static const Abi arm = make_arm();
  static const Abi mips = make_mips();
  // PowerPC SysV (EABI): r3-r10, f1-f8, the stack past the back chain and
  // the LR save word.
  static const Abi ppc{numbered("r", 8, 3), numbered("f", 8, 1), false, 8, 4, "r3", "f1", false};
  static const Abi riscv32{numbered("a", 8), numbered("fa", 8), false, 0, 4, "a0", "fa0", false};
  // cdecl and stdcall: everything on the stack past the return address
  // (stdcall only pops it in the callee).
  static const Abi x86{{}, {}, false, 4, 4, "EAX", "ST0", false};
  if (language.starts_with("x86:LE:64")) return pe ? &win64 : &sysv;
  if (language.starts_with("AARCH64")) return &aarch64;
  if (language.starts_with("RISCV") && language.find(":64:") != std::string::npos) return &riscv;
  if (language.starts_with("ARM:") && is_32(language)) return &arm;
  if (language.starts_with("MIPS:") && is_32(language)) return &mips;
  if (language.starts_with("PowerPC:") && is_32(language)) return &ppc;
  if (language.starts_with("RISCV:") && is_32(language)) return &riscv32;
  if (language.starts_with("x86:LE:32")) return &x86;
  return nullptr;
}

bool supports(const std::string &language_id, const loader::Image &image) {
  if (abi_for(language_id, image.format == loader::Format::pe) == nullptr) return false;
  // 32-bit: the conventions measured against the source (docs/infer.md,
  // "32-bit processors"); the others have tables for rk-infer only.
  if (image.bits == 32) return language_id.starts_with("ARM:") || language_id.starts_with("MIPS:") || language_id.starts_with("PowerPC:");
  return true;
}

std::optional<ArgPos> arg_position(const Abi &abi, const Slot &s) {
  if (s.reg.empty()) {
    if (s.stack < abi.stack_base) return std::nullopt;
    return ArgPos{2, static_cast<int>((s.stack - abi.stack_base) / abi.stack_slot)};
  }
  for (std::size_t i = 0; i < abi.int_regs.size(); ++i)
    if (s.reg == abi.int_regs[i]) return ArgPos{0, static_cast<int>(i)};
  for (std::size_t i = 0; i < abi.float_regs.size(); ++i)
    if (s.reg == abi.float_regs[i]) return ArgPos{1, static_cast<int>(i)};
  for (const auto &[name, pos] : abi.aliases)
    if (s.reg == name) return pos;
  return std::nullopt;
}

bool float_return(const Abi &abi, const std::string &reg) {
  if (reg == abi.float_ret) return true;
  for (const std::string &r : abi.float_ret_aliases)
    if (reg == r) return true;
  return false;
}

std::optional<std::size_t> int_index(const Abi &abi, const Slot &s) {
  auto pos = arg_position(abi, s);
  if (!pos || pos->cls == 1) return std::nullopt;
  if (pos->cls == 2) {
    // Only where the stack holds the arguments past the integer
    // registers of a convention whose registers it extends (the 32-bit
    // ones; a 64-bit stack argument is rare and may follow floats).
    if (abi.stack_slot != 4) return std::nullopt;
    return abi.int_regs.size() + static_cast<std::size_t>(pos->index);
  }
  return static_cast<std::size_t>(pos->index);
}

int order_key(const Abi &abi, const ArgPos &p) {
  if (p.cls == 2) return 1000 + p.index;
  if (abi.positional) return p.index * 2 + p.cls;
  return p.cls * 100 + p.index;
}

}  // namespace revkit::infer
