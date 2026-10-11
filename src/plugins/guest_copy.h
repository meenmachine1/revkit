// Copies into and out of a plugin's linear memory (see guest_copy.cc).
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace revkit::plugins::detail {

void guest_write(std::uint8_t *dst, const void *src, std::size_t n);
void guest_read(void *dst, const std::uint8_t *src, std::size_t n);

inline std::string guest_string(const std::uint8_t *src, std::size_t n) {
  std::string s(n, '\0');
  guest_read(s.data(), src, n);
  return s;
}

}  // namespace revkit::plugins::detail
