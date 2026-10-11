#include "fuzz_common.hh"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  using namespace revkit::loader;
  LoadOptions options;
  if (size > 0 && (data[size - 1] & 1) != 0) options.image_base = 0x10000;
  return fuzz::run(data, size, [&](std::shared_ptr<const Bytes> b) { return parse_pe(std::move(b), options); });
}
