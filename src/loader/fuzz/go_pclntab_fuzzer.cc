// Go's pclntab reader (gopclntab.hh) on hostile bytes. The first byte picks
// the path: the table parser over the input (with and without lines, a
// text start and a pointer function that moves every pointer), or an ELF,
// PE or Mach-O parsed and searched whole (read_go_pclntab: the named
// sections, the magic scan, the moduledata search; guess_language's Go
// check), and the display names of what it finds.
#include "revkit/loader/gopclntab.hh"
#include "revkit/loader/load.hh"

#include <cstring>
#include <memory>

using namespace revkit::loader;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  if (size == 0) return 0;
  const std::uint8_t mode = data[0] % 4;
  ++data;
  --size;
  auto names = [](const GoPclntab &t) {
    std::size_t n = 0;
    for (const GoFunction &f : t.functions) n += go_display_name(f.name).size() + go_function_no_return(f.name);
    return n;
  };
  if (mode < 3) {
    std::span<const std::byte> in(reinterpret_cast<const std::byte *>(data), size);
    GoPclntabOptions o;
    o.lines = mode != 1;
    if (mode == 2) o.text_start = 0xffffffffffff0000ull;  // entries that wrap
    GoPointerFn moved = [](std::uint64_t at, std::uint64_t raw) { return raw ^ at; };
    std::string error;
    auto t = parse_go_pclntab(in, 0x400000, mode == 2 ? moved : GoPointerFn{}, o, &error);
    if (t) (void)names(*t);
  } else {
    auto bytes = std::make_shared<Bytes>(size);
    if (size) std::memcpy(bytes->data(), data, size);
    try {
      Image img = parse(bytes);
      std::string error;
      auto t = read_go_pclntab(img, &error);
      if (t) (void)names(*t);
      (void)guess_language(img);
    } catch (const LoadError &) {
    }
  }
  return 0;
}
