#include "fuzz_common.hh"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  using namespace revkit::loader;
  // Alternate load options on a byte of the input so rebasing is covered.
  LoadOptions options;
  if (size > 0 && (data[size - 1] & 1) != 0) options.ghidra_image_base = true;
  if (size > 0 && (data[size - 1] & 2) != 0) options.image_base = 0xffffffffffff0000ULL;
  return fuzz::run(data, size, [&](std::shared_ptr<const Bytes> b) { return parse_elf(std::move(b), options); });
}
