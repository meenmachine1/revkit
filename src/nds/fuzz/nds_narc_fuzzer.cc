// NARC archives (and through them NitroFS's name table).
#include "revkit/nds/rom.hh"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  std::span<const std::uint8_t> d(data, size);
  std::string e;
  if (auto n = revkit::nds::parse_narc(d, &e, 4096))
    for (const auto &f : n->files)
      if (std::uint64_t{f.offset} + f.size > size) __builtin_trap();
  return 0;
}
