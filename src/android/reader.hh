// Bounded little-endian reads over a byte span: every read checks its
// range and throws Error naming what was being read. Internal.
#pragma once

#include "revkit/android/android.hh"

#include <algorithm>
#include <cstring>
#include <string>

namespace revkit::android::detail {

class Reader {
 public:
  explicit Reader(Bytes b, bool big_endian = false) : b_(b), be_(big_endian) {}
  std::size_t size() const { return b_.size(); }
  Bytes bytes() const { return b_; }
  bool fits(std::uint64_t off, std::uint64_t n) const { return off <= b_.size() && n <= b_.size() - off; }
  void need(std::uint64_t off, std::uint64_t n, const char *what) const {
    if (!fits(off, n)) throw Error(std::string(what) + " lies outside the data");
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
  // Up to the first NUL (at most max bytes; none found: "" and false).
  bool cstr(std::uint64_t off, std::size_t max, std::string &out) const {
    if (off >= b_.size()) return false;
    const std::size_t n = std::min<std::uint64_t>(max, b_.size() - off);
    const auto *p = reinterpret_cast<const char *>(b_.data() + off);
    const void *z = std::memchr(p, 0, n);
    if (z == nullptr) return false;
    out.assign(p, static_cast<const char *>(z) - p);
    return true;
  }
  Bytes sub(std::uint64_t off, std::uint64_t n, const char *what) const {
    need(off, n, what);
    return b_.subspan(off, n);
  }

 private:
  Bytes b_;
  bool be_;
};

// UTF-16 code units to UTF-8 (unpaired surrogates as U+FFFD).
std::string utf16_to_utf8(const std::uint16_t *units, std::size_t n);
void append_utf8(std::string &out, std::uint32_t cp);

// Valid UTF-8 from what a format calls UTF-8 or modified UTF-8 (U+FFFD
// for what doesn't decode).
std::string clean_utf8(std::string_view s);

// Lowercase hex of bytes.
std::string hex_bytes(Bytes b);

}  // namespace revkit::android::detail
