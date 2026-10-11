// Shared body for the loader fuzz targets: parse, then touch everything the
// parser produced so out-of-bounds offsets in the result surface too.
#pragma once

#include "revkit/loader/load.hh"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>

namespace revkit::loader::fuzz {

template <class Parse>
int run(const std::uint8_t *data, std::size_t size, Parse parse) {
  auto bytes = std::make_shared<Bytes>(size);
  for (std::size_t i = 0; i < size; ++i) (*bytes)[i] = std::byte{data[i]};
  try {
    Image img = parse(std::move(bytes));
    std::array<std::byte, 64> buf{};
    for (const Region &r : img.memory.regions()) {
      img.memory.read(r.start, buf);
      img.memory.read(r.last() - 31, buf);  // straddles the region end
    }
    for (const Block &b : img.blocks) img.memory.read(b.start, buf);
    for (const Symbol &s : img.symbols) img.memory.read(s.value, buf);
    for (const Export &e : img.exports) img.memory.read(e.address, buf);
    for (const FunctionRange &f : img.function_ranges) img.memory.read(f.start, buf);
    if (img.entry) img.memory.read(*img.entry, buf);
    (void)guess_language(img);
  } catch (const LoadError &) {
  }
  return 0;
}

}  // namespace revkit::loader::fuzz
