// libFuzzer target: every demangler entry point on arbitrary symbols.
#include "revkit/demangle/demangle.h"

#include <cstddef>
#include <cstdint>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  std::string_view s(reinterpret_cast<const char *>(data), size);
  (void)revkit::demangle::demangle(s);
  (void)revkit::demangle::demangle_itanium(s, false);
  (void)revkit::demangle::demangle_microsoft(s);
  (void)revkit::demangle::itanium_function_parts(s);
  return 0;
}
