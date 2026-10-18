// revkit::objc's scan and markup over any Mach-O the loader accepts.
#include "revkit/loader/load.hh"
#include "revkit/objc/objc.h"

#include <cstddef>
#include <cstdint>
#include <memory>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  using namespace revkit;
  auto bytes = std::make_shared<loader::Bytes>(size);
  for (std::size_t i = 0; i < size; ++i) (*bytes)[i] = std::byte{data[i]};
  try {
    const loader::Image img = loader::parse_macho(std::move(bytes));
    const objc::Metadata md = objc::scan(img);
    (void)objc::markup(img, md);
  } catch (const loader::LoadError &) {
  }
  return 0;
}
