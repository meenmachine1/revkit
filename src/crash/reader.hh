// Bounded reads over a dump's bytes (either byte order): every read checks
// its range and throws Error naming what was read. Internal.
#pragma once

#include "revkit/crash/crash.hh"

#include <algorithm>
#include <cstring>
#include <string>

namespace revkit::crash::detail {

class Reader {
 public:
  explicit Reader(Bytes b, bool big_endian = false) : b_(b), be_(big_endian) {}
  std::size_t size() const { return b_.size(); }
  bool fits(std::uint64_t off, std::uint64_t n) const { return off <= b_.size() && n <= b_.size() - off; }
  void need(std::uint64_t off, std::uint64_t n, const char *what) const {
    if (!fits(off, n)) throw Error(std::string(what) + " lies outside the file");
  }
  std::uint8_t u8(std::uint64_t off, const char *what = "a byte") const {
    need(off, 1, what);
    return static_cast<std::uint8_t>(b_[off]);
  }
  std::uint16_t u16(std::uint64_t off, const char *what = "a 16-bit value") const {
    need(off, 2, what);
    const auto *p = reinterpret_cast<const unsigned char *>(b_.data() + off);
    return be_ ? static_cast<std::uint16_t>(p[0] << 8 | p[1]) : static_cast<std::uint16_t>(p[1] << 8 | p[0]);
  }
  std::uint32_t u32(std::uint64_t off, const char *what = "a 32-bit value") const {
    need(off, 4, what);
    const auto *p = reinterpret_cast<const unsigned char *>(b_.data() + off);
    return be_ ? (std::uint32_t(p[0]) << 24 | std::uint32_t(p[1]) << 16 | std::uint32_t(p[2]) << 8 | p[3])
               : (std::uint32_t(p[3]) << 24 | std::uint32_t(p[2]) << 16 | std::uint32_t(p[1]) << 8 | p[0]);
  }
  std::uint64_t u64(std::uint64_t off, const char *what = "a 64-bit value") const {
    const std::uint64_t a = u32(off, what), b = u32(off + 4, what);
    return be_ ? (a << 32 | b) : (b << 32 | a);
  }
  std::uint64_t word(std::uint64_t off, bool wide, const char *what = "a word") const { return wide ? u64(off, what) : u32(off, what); }
  // Up to the first NUL within max bytes (the whole run when there is none).
  std::string str(std::uint64_t off, std::size_t max) const {
    if (off >= b_.size()) return {};
    const std::size_t n = std::min<std::uint64_t>(max, b_.size() - off);
    const auto *p = reinterpret_cast<const char *>(b_.data() + off);
    const void *z = std::memchr(p, 0, n);
    return std::string(p, z ? static_cast<const char *>(z) - p : n);
  }
  // `n` bytes as they are, least significant first (byte-swapped when big-endian).
  std::vector<std::uint8_t> le_bytes(std::uint64_t off, std::size_t n, const char *what) const {
    need(off, n, what);
    std::vector<std::uint8_t> v(n);
    std::memcpy(v.data(), b_.data() + off, n);
    if (be_) std::reverse(v.begin(), v.end());
    return v;
  }
  Bytes bytes() const { return b_; }

 private:
  Bytes b_;
  bool be_;
};

// Printable ASCII (anything else as '?').
std::string clean(std::string_view s);
// A UTF-16LE string of `units` code units as UTF-8 (stops at a NUL).
std::string utf16(const Reader &r, std::uint64_t off, std::size_t units);
std::string hex(std::uint64_t v);
// CrashDump::reason from the signal or exception fields.
void describe(CrashDump &d);
void sort_memory(CrashDump &d);

}  // namespace revkit::crash::detail
