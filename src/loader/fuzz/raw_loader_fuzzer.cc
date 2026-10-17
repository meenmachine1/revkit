// The raw loader (raw.cc): Intel HEX, S-records and flat binaries, the
// container detection, and parse_raw_region's command-line spelling. The
// first byte picks the container and the options; the rest is the file.
#include "revkit/loader/load.hh"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  using namespace revkit::loader;
  if (size < 1) return 0;
  const std::uint8_t sel = data[0];
  ++data;
  --size;
  // A region spec from the first line (up to 128 bytes).
  std::size_t nl = 0;
  while (nl < size && nl < 128 && data[nl] != '\n') ++nl;
  try {
    (void)parse_raw_region(std::string_view(reinterpret_cast<const char *>(data), nl));
  } catch (const LoadError &) {
  }
  auto bytes = std::make_shared<Bytes>(size);
  for (std::size_t i = 0; i < size; ++i) (*bytes)[i] = std::byte{data[i]};
  (void)detect_raw_container(*bytes);
  RawOptions o;
  static constexpr std::array<const char *, 4> kLanguages = {"ARM:LE:32:v8", "x86:LE:64:default", "8051:BE:16:default",
                                                             "MIPS:BE:32:default"};
  o.language = kLanguages[sel & 3];
  static constexpr std::array<RawContainer, 4> kContainers = {RawContainer::detect, RawContainer::binary,
                                                              RawContainer::ihex, RawContainer::srec};
  o.container = kContainers[(sel >> 2) & 3];
  if (sel & 0x10) o.base = 0xfffffffffffff000ull;  // near the top: wraps
  if (sel & 0x20) o.offset = size / 2;
  if (sel & 0x40) o.length = size / 3;
  if (sel & 0x80) {
    RawRegion r;
    r.name = "ram";
    r.start = 0x20000000;
    r.size = 0x1000;
    r.initialized = true;
    r.file_offset = 0;
    r.file_size = size;
    o.regions.push_back(r);
  }
  try {
    const Image img = parse_raw(std::move(bytes), o);
    std::array<std::byte, 64> buf{};
    for (const Region &r : img.memory.regions()) {
      img.memory.read(r.start, buf);
      img.memory.read(r.last() - 31, buf);
    }
  } catch (const LoadError &) {
  }
  return 0;
}
