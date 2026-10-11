// 128-bit stable fingerprints of encoded values. The query engine compares
// fingerprints instead of values for early cutoff, which lets dependency
// edges be checked after a memo has been evicted to disk or reloaded in a
// later session.
#pragma once

#include <compare>
#include <cstdint>
#include <string>
#include <string_view>

namespace revkit::facts {

struct Fingerprint {
  std::uint64_t lo = 0;
  std::uint64_t hi = 0;

  static Fingerprint of(std::string_view bytes);
  std::string hex() const;

  friend auto operator<=>(const Fingerprint &, const Fingerprint &) = default;
};

}  // namespace revkit::facts
