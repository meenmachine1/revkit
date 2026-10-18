// The Mach-O parser: thin files and universal ones (a slice by name, by
// index, or the default), rebased or not.
#include "fuzz_common.hh"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  using namespace revkit::loader;
  // Alternate load options on the input's last byte.
  LoadOptions options;
  const std::uint8_t k = size > 0 ? data[size - 1] : 0;
  if (k & 1) options.image_base = 0x200000000ULL;
  if (k & 2) options.macho_slice = (k & 4) ? "#1" : "x86_64";
  return fuzz::run(data, size, [&](std::shared_ptr<const Bytes> b) {
    (void)macho_slices(*b);
    Image img = parse_macho(std::move(b), options);
    std::array<std::byte, 8> buf{};
    for (const Relocation &r : img.relocations) {
      img.memory.read(r.address, buf);
      if (r.target) img.memory.read(*r.target, buf);
      (void)relocation_type_name(img, r.type);
    }
    if (img.macho) {
      for (std::uint64_t f : img.macho->function_starts) img.memory.read(f, buf);
      for (const auto &[start, end] : img.macho->data_in_code) img.memory.read(start, buf), img.memory.read(end, buf);
    }
    for (const Section &s : img.sections) (void)section_bytes(img, s);
    return img;
  });
}
