#include "revkit/facts/fingerprint.h"

#include <cstdio>
#include <cstring>

namespace revkit::facts {

namespace {

// MurmurHash3 x64_128 (public domain, Austin Appleby), reading bytes
// little-endian explicitly so fingerprints match across hosts.
std::uint64_t rotl(std::uint64_t x, int r) { return (x << r) | (x >> (64 - r)); }

std::uint64_t fmix(std::uint64_t k) {
  k ^= k >> 33;
  k *= 0xff51afd7ed558ccdULL;
  k ^= k >> 33;
  k *= 0xc4ceb9fe1a85ec53ULL;
  k ^= k >> 33;
  return k;
}

std::uint64_t load_le(const unsigned char *p, std::size_t n) {
  std::uint64_t v = 0;
  for (std::size_t i = 0; i < n; ++i) v |= std::uint64_t{p[i]} << (8 * i);
  return v;
}

}  // namespace

Fingerprint Fingerprint::of(std::string_view bytes) {
  const auto *data = reinterpret_cast<const unsigned char *>(bytes.data());
  const std::size_t len = bytes.size();
  const std::size_t nblocks = len / 16;
  constexpr std::uint64_t c1 = 0x87c37b91114253d5ULL;
  constexpr std::uint64_t c2 = 0x4cf5ad432745937fULL;
  std::uint64_t h1 = 0x9e3779b97f4a7c15ULL;
  std::uint64_t h2 = 0x6a09e667f3bcc909ULL;

  for (std::size_t i = 0; i < nblocks; ++i) {
    std::uint64_t k1 = load_le(data + i * 16, 8);
    std::uint64_t k2 = load_le(data + i * 16 + 8, 8);
    k1 *= c1; k1 = rotl(k1, 31); k1 *= c2; h1 ^= k1;
    h1 = rotl(h1, 27); h1 += h2; h1 = h1 * 5 + 0x52dce729;
    k2 *= c2; k2 = rotl(k2, 33); k2 *= c1; h2 ^= k2;
    h2 = rotl(h2, 31); h2 += h1; h2 = h2 * 5 + 0x38495ab5;
  }

  const unsigned char *tail = data + nblocks * 16;
  std::size_t rest = len & 15;
  if (rest > 8) {
    std::uint64_t k2 = load_le(tail + 8, rest - 8);
    k2 *= c2; k2 = rotl(k2, 33); k2 *= c1; h2 ^= k2;
  }
  if (rest > 0) {
    std::uint64_t k1 = load_le(tail, rest > 8 ? 8 : rest);
    k1 *= c1; k1 = rotl(k1, 31); k1 *= c2; h1 ^= k1;
  }

  h1 ^= len; h2 ^= len;
  h1 += h2; h2 += h1;
  h1 = fmix(h1); h2 = fmix(h2);
  h1 += h2; h2 += h1;
  return {h1, h2};
}

std::string Fingerprint::hex() const {
  char buf[33];
  std::snprintf(buf, sizeof buf, "%016llx%016llx", static_cast<unsigned long long>(hi),
                static_cast<unsigned long long>(lo));
  return buf;
}

}  // namespace revkit::facts
