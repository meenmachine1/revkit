// The PE base relocation reader (relocations.cc, the .reloc directory:
// blocks, their entries, the words they point at) over a hostile PE, and
// the relocation names of what the parser listed. fuzz_pe stops at the
// parser; this reads the directory as the Relocations view does.
#include "revkit/loader/load.hh"

#include <cstddef>
#include <cstdint>
#include <memory>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  using namespace revkit::loader;
  auto bytes = std::make_shared<Bytes>(size);
  for (std::size_t i = 0; i < size; ++i) (*bytes)[i] = std::byte{data[i]};
  try {
    LoadOptions options;
    if (size > 0 && (data[size - 1] & 1) != 0) options.image_base = 0x10000;  // rebased: targets move
    const Image img = parse_pe(std::move(bytes), options);
    for (const Relocation &r : pe_base_relocations(img, std::size_t{1} << 16)) (void)relocation_type_name(img, r.type);
    for (const Relocation &r : img.relocations) (void)relocation_type_name(img, r.type);
  } catch (const LoadError &) {
  }
  return 0;
}
