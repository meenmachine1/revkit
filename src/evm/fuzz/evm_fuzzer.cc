// EVM bytecode as the backend reads it at import (docs/evm.md): the file's
// bytecode (binary or hex text), its layout, then the runtime code's
// analysis and dispatcher, the way image_backend does. The bytes are taken
// as code even when they don't start like solc's, so the stack analysis
// sees arbitrary instruction streams.
#include "revkit/evm/evm.h"

#include <cstddef>
#include <cstdint>
#include <span>

namespace {

void run(std::span<const std::byte> file) {
  const revkit::evm::Layout l = revkit::evm::layout(file);
  if (std::uint64_t{l.runtime_offset} + l.runtime_size > file.size()) __builtin_trap();
  const auto runtime = file.subspan(l.runtime_offset, l.runtime_size ? l.runtime_size : file.size() - l.runtime_offset);
  const revkit::evm::Analysis a = revkit::evm::analyze(runtime);
  for (const auto &[at, tag] : a.direct)
    if (at >= runtime.size()) __builtin_trap();
  for (const auto &i : a.insns)
    if (i.pc >= runtime.size()) __builtin_trap();
  if (a.meta && std::uint64_t{a.meta->offset} + a.meta->size > runtime.size()) __builtin_trap();
  for (const auto &s : revkit::evm::dispatcher(a.insns)) {
    (void)revkit::evm::selector_name(s.selector);
    if (const auto *k = revkit::evm::known_signature(s.selector)) (void)revkit::evm::signature_name(k->signature);
  }
  if (l.creation) (void)revkit::evm::analyze(file.subspan(0, l.runtime_offset));
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  const std::span<const std::byte> bytes(reinterpret_cast<const std::byte *>(data), size);
  if (auto code = revkit::evm::bytecode_of(bytes)) run(*code);
  run(bytes);
  for (const auto &i : revkit::evm::disassemble(bytes)) (void)revkit::evm::mnemonic(i.op);
  return 0;
}
