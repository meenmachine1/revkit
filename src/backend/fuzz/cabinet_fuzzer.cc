// ExpandCabinet (symbol_server.cc): a .pd_ cabinet from a symbol server or
// a store, expanded in memory (MSZIP or stored). It had a ~4 GiB
// out-of-bounds read when a 32-bit sum wrapped (docs/bug-scrub.md).
#include "symbol_server.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  std::string out;
  (void)revkit::backend::ExpandCabinet(std::string_view(reinterpret_cast<const char *>(data), size), out, 16u << 20);
  return 0;
}
