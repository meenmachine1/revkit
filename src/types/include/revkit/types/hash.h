// Content hashes: SHA-256, and the 128-bit truncation used as type identity.
#pragma once

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>

namespace revkit::types {

class Sha256 {
 public:
  using Digest = std::array<std::uint8_t, 32>;

  Sha256();
  void update(std::span<const std::uint8_t> data);
  void update(std::string_view s) {
    update({reinterpret_cast<const std::uint8_t *>(s.data()), s.size()});
  }
  Digest finish();

  static Digest of(std::span<const std::uint8_t> data) {
    Sha256 h;
    h.update(data);
    return h.finish();
  }

 private:
  void block(const std::uint8_t *p);
  std::array<std::uint32_t, 8> state_;
  std::array<std::uint8_t, 64> buf_{};
  std::size_t buf_len_ = 0;
  std::uint64_t total_ = 0;
};

std::string to_hex(std::span<const std::uint8_t> bytes);

// A type's identity: the first 16 bytes of a SHA-256 over its canonical
// encoding (see docs/types.md).
struct Hash {
  std::array<std::uint8_t, 16> bytes{};

  static Hash from_digest(const Sha256::Digest &d) {
    Hash h;
    std::memcpy(h.bytes.data(), d.data(), h.bytes.size());
    return h;
  }
  std::string hex() const { return to_hex(bytes); }
  friend auto operator<=>(const Hash &, const Hash &) = default;
};

}  // namespace revkit::types

template <>
struct std::hash<revkit::types::Hash> {
  std::size_t operator()(const revkit::types::Hash &h) const noexcept {
    std::size_t v;
    std::memcpy(&v, h.bytes.data(), sizeof v);
    return v;
  }
};
