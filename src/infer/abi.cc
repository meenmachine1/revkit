#include "abi.h"

#include "revkit/infer/infer.h"

namespace revkit::infer {

namespace {

std::vector<std::string> numbered(const std::string &prefix, int n) {
  std::vector<std::string> out;
  for (int i = 0; i < n; ++i) out.push_back(prefix + std::to_string(i));
  return out;
}

}  // namespace

const Abi *abi_for(const std::string &language, bool pe) {
  static const Abi sysv{{"RDI", "RSI", "RDX", "RCX", "R8", "R9"}, numbered("XMM", 8), false, 8, 8, "RAX", "XMM0", true};
  static const Abi win64{{"RCX", "RDX", "R8", "R9"}, numbered("XMM", 4), true, 0x28, 8, "RAX", "XMM0", false};
  static const Abi aarch64{numbered("x", 8), numbered("q", 8), false, 0, 8, "x0", "q0", false};
  static const Abi riscv{numbered("a", 8), numbered("fa", 8), false, 0, 8, "a0", "fa0", false};
  if (language.starts_with("x86:LE:64")) return pe ? &win64 : &sysv;
  if (language.starts_with("AARCH64")) return &aarch64;
  if (language.starts_with("RISCV") && language.find(":64:") != std::string::npos) return &riscv;
  return nullptr;
}

bool supports(const std::string &language_id, const loader::Image &image) {
  return abi_for(language_id, image.format == loader::Format::pe) != nullptr;
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
  return std::nullopt;
}

int order_key(const Abi &abi, const ArgPos &p) {
  if (p.cls == 2) return 1000 + p.index;
  if (abi.positional) return p.index * 2 + p.cls;
  return p.cls * 100 + p.index;
}

}  // namespace revkit::infer
