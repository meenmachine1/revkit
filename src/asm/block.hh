// Bit patterns over a byte stream (Ghidra's AssemblyPatternBlock) and
// partially known 64-bit values (Ghidra's MaskedLong).
//
// A Block says, for each byte from the start of the instruction (or of the
// context words, laid out big-endian as SLEIGH reads them), which bits are
// required (mask) and their values. Bit numbering follows SLEIGH: bit 0 is
// the most significant bit of byte 0.
#pragma once

#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace revkit::assembler::detail {

inline constexpr int kMaxBytes = 32;

struct Block {
  std::array<std::uint8_t, kMaxBytes> mask{};
  std::array<std::uint8_t, kMaxBytes> val{};
  std::uint8_t len = 0;  // bytes that may hold mask bits

  bool empty() const {
    for (int i = 0; i < len; ++i)
      if (mask[i]) return false;
    return true;
  }
  // Combine two requirements; nullopt when they disagree on a bit.
  static std::optional<Block> combine(const Block &a, const Block &b) {
    Block r = a.len >= b.len ? a : b;
    const Block &o = a.len >= b.len ? b : a;
    for (int i = 0; i < o.len; ++i) {
      const std::uint8_t both = r.mask[i] & o.mask[i];
      if ((r.val[i] & both) != (o.val[i] & both)) return std::nullopt;
      r.mask[i] |= o.mask[i];
      r.val[i] = static_cast<std::uint8_t>((r.val[i] & r.mask[i]) | (o.val[i] & o.mask[i]));
    }
    return r;
  }
  bool merge(const Block &o) {
    auto c = combine(*this, o);
    if (!c) return false;
    *this = *c;
    return true;
  }
  // The same pattern `n` bytes later; false if it would run past kMaxBytes.
  bool shift(int n) {
    if (n == 0) return true;
    int last = len;
    while (last > 0 && mask[last - 1] == 0) --last;
    if (last + n > kMaxBytes) return false;
    for (int i = last - 1; i >= 0; --i) {
      mask[i + n] = mask[i];
      val[i + n] = val[i];
    }
    for (int i = 0; i < n; ++i) mask[i] = val[i] = 0;
    len = static_cast<std::uint8_t>(last + n);
    return true;
  }
  void set_bits(int byte, std::uint8_t m, std::uint8_t v) {
    if (byte + 1 > len) len = static_cast<std::uint8_t>(byte + 1);
    mask[byte] |= m;
    val[byte] = static_cast<std::uint8_t>((val[byte] & ~m) | (v & m));
  }
  // Requirements on bits outside `keep` dropped.
  void clear_bits(int byte, std::uint8_t m) {
    if (byte >= len) return;
    mask[byte] &= static_cast<std::uint8_t>(~m);
    val[byte] &= mask[byte];
  }
  // Whether `bytes` (missing bytes read as unknown) satisfy every required bit.
  bool matches(std::span<const std::uint8_t> bytes) const {
    for (int i = 0; i < len; ++i) {
      if (!mask[i]) continue;
      if (i >= static_cast<int>(bytes.size())) return false;
      if ((bytes[i] & mask[i]) != val[i]) return false;
    }
    return true;
  }
  int last_masked() const {  // index past the last byte with a mask bit
    int last = len;
    while (last > 0 && mask[last - 1] == 0) --last;
    return last;
  }
  friend bool operator==(const Block &a, const Block &b) {
    const int n = std::max(a.len, b.len);
    for (int i = 0; i < n; ++i) {
      const std::uint8_t am = i < a.len ? a.mask[i] : 0, bm = i < b.len ? b.mask[i] : 0;
      const std::uint8_t av = i < a.len ? a.val[i] : 0, bv = i < b.len ? b.val[i] : 0;
      if (am != bm || (av & am) != (bv & bm)) return false;
    }
    return true;
  }
  std::string str() const;
};

// A 64-bit value whose bits are known where `msk` is set.
struct Masked {
  std::uint64_t msk = 0;
  std::uint64_t val = 0;

  static Masked known(std::uint64_t v) { return {~std::uint64_t{0}, v}; }
  static Masked unknown() { return {}; }
  static Masked of(std::uint64_t m, std::uint64_t v) { return {m, v & m}; }
  bool full() const { return msk == ~std::uint64_t{0}; }
  bool none() const { return msk == 0; }
  bool agrees(const Masked &o) const { return ((val ^ o.val) & msk & o.msk) == 0; }
  std::optional<Masked> combine(const Masked &o) const {
    if (!agrees(o)) return std::nullopt;
    return Masked{msk | o.msk, (val & msk) | (o.val & o.msk)};
  }
  Masked shl(unsigned n) const {
    if (n >= 64) return known(0);
    // The low n bits become known zeros.
    return {(msk << n) | ((std::uint64_t{1} << n) - 1), val << n};
  }
  Masked shr_logical(unsigned n) const {  // high bits become known zeros
    if (n >= 64) return known(0);
    return {(msk >> n) | ~(~std::uint64_t{0} >> n), val >> n};
  }
  Masked shr_arith(unsigned n) const {
    if (n >= 64) n = 63;
    const bool sign_known = msk >> 63;
    const bool sign = val >> 63;
    std::uint64_t m = msk >> n, v = val >> n;
    const std::uint64_t top = n ? ~(~std::uint64_t{0} >> n) : 0;
    if (sign_known) {
      m |= top;
      if (sign) v |= top;
    }
    return {m, v};
  }
  // Shifted right with the vacated high bits unknown: the inverse of shl.
  Masked shr_positional(unsigned n) const {
    if (n >= 64) return unknown();
    return {msk >> n, val >> n};
  }
  Masked zext(unsigned bits) const {
    if (bits >= 64) return *this;
    const std::uint64_t keep = (std::uint64_t{1} << bits) - 1;
    return {(msk & keep) | ~keep, val & keep};
  }
  Masked sext(unsigned bits) const {
    if (bits >= 64 || bits == 0) return *this;
    const std::uint64_t keep = (std::uint64_t{1} << bits) - 1;
    const std::uint64_t sbit = std::uint64_t{1} << (bits - 1);
    Masked r{msk & keep, val & keep};
    if (msk & sbit) {
      r.msk |= ~keep;
      if (val & sbit) r.val |= ~keep;
    }
    return r;
  }
  Masked operator~() const { return {msk, ~val & msk}; }
  Masked bit_and(const Masked &o) const {
    // Known zero on either side gives a known zero.
    const std::uint64_t kz = (msk & ~val) | (o.msk & ~o.val);
    const std::uint64_t k = (msk & o.msk) | kz;
    return {k, val & o.val & k};
  }
  Masked bit_or(const Masked &o) const {
    const std::uint64_t ko = (msk & val) | (o.msk & o.val);
    const std::uint64_t k = (msk & o.msk) | ko;
    return {k, (val | o.val) & k};
  }
  Masked bit_xor(const Masked &o) const {
    const std::uint64_t k = msk & o.msk;
    return {k, (val ^ o.val) & k};
  }
  // Addition: exact only when both are fully known; else the known low bits.
  Masked add(const Masked &o) const {
    if (full() && o.full()) return known(val + o.val);
    const std::uint64_t both = msk & o.msk;
    // Known through the lowest unknown bit of either.
    const unsigned low = static_cast<unsigned>(std::countr_one(both));
    if (low == 0) return unknown();
    const std::uint64_t m = low >= 64 ? ~std::uint64_t{0} : (std::uint64_t{1} << low) - 1;
    return {m, (val + o.val) & m};
  }
  Masked neg() const {
    if (full()) return known(~val + 1);
    return add_known(~*this, 1);
  }
  static Masked add_known(const Masked &a, std::uint64_t k) { return a.add(known(k)); }
  Masked mul(const Masked &o) const {
    if (full() && o.full()) return known(val * o.val);
    return unknown();
  }
  // Fits a field of `bits` (signed: as two's complement): every known bit
  // above the field agrees with the extension.
  bool fits(unsigned bits, bool is_signed) const {
    if (bits >= 64) return true;
    const std::uint64_t high = ~std::uint64_t{0} << bits;
    if (!is_signed) return (val & msk & high) == 0;
    // Bits [bits-1, 64) all equal (where known).
    const std::uint64_t hs = ~std::uint64_t{0} << (bits - 1);
    const std::uint64_t ones = val & msk & hs, zeros = ~val & msk & hs;
    return ones == 0 || zeros == 0;
  }
};

}  // namespace revkit::assembler::detail
