// Copies into and out of a plugin's linear memory. Built without TSan
// instrumentation (see CMakeLists.txt): wasmtime maps guest memory with
// raw syscalls TSan never sees, so when a new instance's memory lands where
// a finished one's was, TSan reports the host's copies into the two as a
// race. A guest's memory belongs to one store, used by one thread at a
// time, so these copies can't race; every other access stays checked.
// Plain loops, compiled so they don't become calls to the intercepted
// memcpy.
#include "guest_copy.h"

namespace revkit::plugins::detail {

void guest_write(std::uint8_t *dst, const void *src, std::size_t n) {
  const auto *s = static_cast<const std::uint8_t *>(src);
  for (std::size_t i = 0; i < n; ++i) dst[i] = s[i];
}

void guest_read(void *dst, const std::uint8_t *src, std::size_t n) {
  auto *d = static_cast<std::uint8_t *>(dst);
  for (std::size_t i = 0; i < n; ++i) d[i] = src[i];
}

}  // namespace revkit::plugins::detail
