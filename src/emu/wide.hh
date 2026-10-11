// Fixed-width unsigned integers of 1 to 64 bytes, the values p-code ops
// compute on. Varnodes wider than eight bytes (x86 XMM/YMM/ZMM, AArch64 Q
// registers, the 128-bit dividend of x86-64's DIV) are common enough that
// the interpreter can't stop at uint64_t, which is where Ghidra's C++
// OpBehavior classes stop.
#pragma once

#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <cstring>

namespace revkit::emu::detail {

constexpr std::uint32_t kMaxValueBytes = 64;
constexpr std::uint32_t kLimbs = kMaxValueBytes / 8;

struct Wide {
  std::uint32_t size = 0;  // bytes
  std::array<std::uint64_t, kLimbs> w{};

  static Wide of(std::uint32_t size, std::uint64_t v) {
    Wide x;
    x.size = size;
    x.w[0] = v;
    x.mask();
    return x;
  }
  std::uint32_t limbs() const { return (size + 7) / 8; }
  std::uint64_t lo() const { return w[0]; }
  bool zero() const {
    for (std::uint32_t i = 0; i < limbs(); ++i)
      if (w[i] != 0) return false;
    return true;
  }
  // Clears the bits above size*8.
  void mask() {
    const std::uint32_t n = limbs();
    for (std::uint32_t i = n; i < kLimbs; ++i) w[i] = 0;
    const std::uint32_t rem = size % 8;
    if (n > 0 && rem != 0) w[n - 1] &= (std::uint64_t{1} << (8 * rem)) - 1;
  }
  bool bit(std::uint32_t i) const { return i < 8 * kMaxValueBytes && ((w[i / 64] >> (i % 64)) & 1) != 0; }
  bool sign() const { return size != 0 && bit(8 * size - 1); }
  // Bytes, least significant first.
  void to_le(std::uint8_t *out) const {
    for (std::uint32_t i = 0; i < size; ++i) out[i] = static_cast<std::uint8_t>(w[i / 8] >> (8 * (i % 8)));
  }
  static Wide from_le(std::uint32_t size, const std::uint8_t *in) {
    Wide x;
    x.size = size;
    for (std::uint32_t i = 0; i < size; ++i) x.w[i / 8] |= std::uint64_t{in[i]} << (8 * (i % 8));
    return x;
  }
  // Resized: zero-extended or truncated.
  Wide resized(std::uint32_t n) const {
    Wide x = *this;
    x.size = n;
    x.mask();
    return x;
  }
  Wide sext(std::uint32_t n) const {
    Wide x = *this;
    x.size = n;
    if (sign())
      for (std::uint32_t i = 8 * size; i < 8 * n; ++i) x.w[i / 64] |= std::uint64_t{1} << (i % 64);
    x.mask();
    return x;
  }
  // Two's-complement value clamped to int64 (for shift amounts, indices).
  std::uint64_t clamp_u64() const {
    for (std::uint32_t i = 1; i < limbs(); ++i)
      if (w[i] != 0) return ~std::uint64_t{0};
    return w[0];
  }
};

inline bool operator==(const Wide &a, const Wide &b) {
  for (std::uint32_t i = 0; i < kLimbs; ++i)
    if (a.w[i] != b.w[i]) return false;
  return true;
}

inline Wide add(const Wide &a, const Wide &b) {
  Wide r;
  r.size = a.size;
  unsigned __int128 carry = 0;
  for (std::uint32_t i = 0; i < a.limbs(); ++i) {
    unsigned __int128 s = static_cast<unsigned __int128>(a.w[i]) + b.w[i] + carry;
    r.w[i] = static_cast<std::uint64_t>(s);
    carry = s >> 64;
  }
  r.mask();
  return r;
}
inline Wide bit_not(const Wide &a) {
  Wide r = a;
  for (std::uint32_t i = 0; i < a.limbs(); ++i) r.w[i] = ~a.w[i];
  r.mask();
  return r;
}
inline Wide negate(const Wide &a) { return add(bit_not(a), Wide::of(a.size, 1)); }
inline Wide sub(const Wide &a, const Wide &b) { return add(a, negate(b.resized(a.size))); }

inline bool ult(const Wide &a, const Wide &b) {
  for (std::uint32_t i = kLimbs; i-- > 0;)
    if (a.w[i] != b.w[i]) return a.w[i] < b.w[i];
  return false;
}
inline bool slt(const Wide &a, const Wide &b) {
  const bool sa = a.sign(), sb = b.sign();
  if (sa != sb) return sa;
  return ult(a, b);
}

inline Wide shl(const Wide &a, std::uint64_t n) {
  Wide r;
  r.size = a.size;
  if (n >= 8ull * a.size) return r;
  const std::uint32_t limb = static_cast<std::uint32_t>(n / 64), bits = static_cast<std::uint32_t>(n % 64);
  for (std::uint32_t i = kLimbs; i-- > limb;) {
    std::uint64_t v = a.w[i - limb] << bits;
    if (bits != 0 && i - limb > 0) v |= a.w[i - limb - 1] >> (64 - bits);
    r.w[i] = v;
  }
  r.mask();
  return r;
}
inline Wide lshr(const Wide &a, std::uint64_t n) {
  Wide r;
  r.size = a.size;
  if (n >= 8ull * a.size) return r;
  const std::uint32_t limb = static_cast<std::uint32_t>(n / 64), bits = static_cast<std::uint32_t>(n % 64);
  for (std::uint32_t i = 0; i + limb < kLimbs; ++i) {
    std::uint64_t v = a.w[i + limb] >> bits;
    if (bits != 0 && i + limb + 1 < kLimbs) v |= a.w[i + limb + 1] << (64 - bits);
    r.w[i] = v;
  }
  r.mask();
  return r;
}
inline Wide ashr(const Wide &a, std::uint64_t n) {
  if (!a.sign()) return lshr(a, n);
  if (n >= 8ull * a.size) return bit_not(Wide::of(a.size, 0));
  // Shift the complement and complement back: ~(~a >> n).
  return bit_not(lshr(bit_not(a), n));
}

inline Wide mul(const Wide &a, const Wide &b) {
  Wide r;
  r.size = a.size;
  const std::uint32_t n = a.limbs();
  for (std::uint32_t i = 0; i < n; ++i) {
    unsigned __int128 carry = 0;
    for (std::uint32_t j = 0; i + j < n; ++j) {
      unsigned __int128 t = static_cast<unsigned __int128>(a.w[i]) * b.w[j] + r.w[i + j] + carry;
      r.w[i + j] = static_cast<std::uint64_t>(t);
      carry = t >> 64;
    }
  }
  r.mask();
  return r;
}

// Unsigned division; b must be non-zero.
inline void udivrem(const Wide &a, const Wide &b, Wide &q, Wide &r) {
  q = Wide::of(a.size, 0);
  r = Wide::of(a.size, 0);
  if (a.size <= 8) {
    q.w[0] = a.w[0] / b.w[0];
    r.w[0] = a.w[0] % b.w[0];
    return;
  }
  if (a.size <= 16) {
    auto u = [](const Wide &x) { return (static_cast<unsigned __int128>(x.w[1]) << 64) | x.w[0]; };
    unsigned __int128 qa = u(a) / u(b), ra = u(a) % u(b);
    q.w[0] = static_cast<std::uint64_t>(qa);
    q.w[1] = static_cast<std::uint64_t>(qa >> 64);
    r.w[0] = static_cast<std::uint64_t>(ra);
    r.w[1] = static_cast<std::uint64_t>(ra >> 64);
    q.mask();
    r.mask();
    return;
  }
  const Wide d = b.resized(a.size);
  for (std::uint32_t i = 8 * a.size; i-- > 0;) {
    r = shl(r, 1);
    if (a.bit(i)) r.w[0] |= 1;
    if (!ult(r, d)) {
      r = sub(r, d);
      q.w[i / 64] |= std::uint64_t{1} << (i % 64);
    }
  }
}

inline std::uint32_t popcount(const Wide &a) {
  std::uint32_t n = 0;
  for (std::uint32_t i = 0; i < a.limbs(); ++i) n += static_cast<std::uint32_t>(std::popcount(a.w[i]));
  return n;
}
inline std::uint32_t lzcount(const Wide &a) {
  for (std::uint32_t i = 8 * a.size; i-- > 0;)
    if (a.bit(i)) return 8 * a.size - 1 - i;
  return 8 * a.size;
}

}  // namespace revkit::emu::detail
