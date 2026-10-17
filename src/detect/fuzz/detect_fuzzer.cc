// Processor auto-detection (revkit::detect) on arbitrary bytes, as
// DetectRawLayout and a raw import run it on an uploaded blob: the file's
// segments, each candidate's sweep, the layout of the best, its variant,
// Cortex-M vectors and the memory regions. The first byte narrows the
// candidates (detection of all of them is slow); one thread.
#include "revkit/detect/detect.hh"
#include "revkit/lift/lifter.hh"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <string>

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
  if (const char *root = std::getenv("GHIDRA_INSTALL_DIR")) revkit::lift::initialize(root);
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  using namespace revkit;
  if (size < 1) return 0;
  static constexpr std::array<const char *, 8> kProcessors = {"ARM", "x86", "MIPS", "PowerPC",
                                                              "AARCH64", "RISCV", "8051", "AVR8"};
  detect::Options o;
  o.threads = 1;
  if (data[0] & 0x80) o.processors = {kProcessors[data[0] & 7]};
  const std::span<const std::byte> file(reinterpret_cast<const std::byte *>(data + 1), size - 1);
  try {
    const detect::Report r = detect::detect(file, o);
    (void)r.suggestions.size();
  } catch (const lift::LiftError &) {
  }
  (void)detect::string_offsets(file);
  return 0;
}
