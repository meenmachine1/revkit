// The DS compressions: LZ10, LZ11, Huffman, RLE by their header, and BLZ.
#include "revkit/nds/compress.hh"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  std::span<const std::uint8_t> d(data, size);
  std::string e;
  std::size_t used = 0;
  if (auto out = revkit::nds::decompress(d, 1u << 22, &e, &used)) {
    if (used > size) __builtin_trap();
  }
  (void)revkit::nds::looks_compressed(d, 1u << 22);
  if (auto out = revkit::nds::blz_decompress(d, 1u << 22, &e)) {
    if (out->size() < size) __builtin_trap();
  }
  return 0;
}
