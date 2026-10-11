#include "sha256.hh"

#include <array>
#include <bit>
#include <cstdint>

namespace rklift {

namespace {

constexpr std::array<std::uint32_t, 64> kRound = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

void compress(std::array<std::uint32_t, 8> &h, const std::uint8_t *block) {
  std::array<std::uint32_t, 64> w{};
  for (std::size_t i = 0; i < 16; ++i)
    w[i] = std::uint32_t{block[4 * i]} << 24 | std::uint32_t{block[4 * i + 1]} << 16 |
           std::uint32_t{block[4 * i + 2]} << 8 | std::uint32_t{block[4 * i + 3]};
  for (std::size_t i = 16; i < 64; ++i) {
    std::uint32_t s0 = std::rotr(w[i - 15], 7) ^ std::rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
    std::uint32_t s1 = std::rotr(w[i - 2], 17) ^ std::rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  std::uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], k = h[7];
  for (std::size_t i = 0; i < 64; ++i) {
    std::uint32_t t1 = k + (std::rotr(e, 6) ^ std::rotr(e, 11) ^ std::rotr(e, 25)) + ((e & f) ^ (~e & g)) +
                       kRound[i] + w[i];
    std::uint32_t t2 = (std::rotr(a, 2) ^ std::rotr(a, 13) ^ std::rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
    k = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  h[0] += a;
  h[1] += b;
  h[2] += c;
  h[3] += d;
  h[4] += e;
  h[5] += f;
  h[6] += g;
  h[7] += k;
}

}  // namespace

std::string sha256_hex(std::span<const std::byte> data) {
  std::array<std::uint32_t, 8> h = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  const auto *p = reinterpret_cast<const std::uint8_t *>(data.data());
  std::size_t n = data.size();
  std::size_t full = n / 64;
  for (std::size_t i = 0; i < full; ++i) compress(h, p + 64 * i);

  // Final block(s): remaining bytes, 0x80, zero pad, 64-bit big-endian bit length.
  std::array<std::uint8_t, 128> tail{};
  std::size_t rem = n % 64;
  for (std::size_t i = 0; i < rem; ++i) tail[i] = p[64 * full + i];
  tail[rem] = 0x80;
  std::size_t tail_len = rem < 56 ? 64 : 128;
  std::uint64_t bits = static_cast<std::uint64_t>(n) * 8;
  for (std::size_t i = 0; i < 8; ++i) tail[tail_len - 1 - i] = static_cast<std::uint8_t>(bits >> (8 * i));
  compress(h, tail.data());
  if (tail_len == 128) compress(h, tail.data() + 64);

  static constexpr char digits[] = "0123456789abcdef";
  std::string out;
  for (std::uint32_t v : h)
    for (int shift = 28; shift >= 0; shift -= 4) out.push_back(digits[(v >> shift) & 0xf]);
  return out;
}

}  // namespace rklift
