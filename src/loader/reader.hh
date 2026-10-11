// Bounds-checked, endian-aware reads over a byte buffer. Every accessor
// validates its range and throws LoadError instead of reading out of bounds.
#pragma once

#include "revkit/loader/image.hh"

#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>

namespace revkit::loader::detail {

std::string hex(std::uint64_t v);

[[noreturn]] void fail(std::string_view what);

inline std::uint64_t checked_add(std::uint64_t a, std::uint64_t b, std::string_view what) {
  std::uint64_t r = 0;
  if (__builtin_add_overflow(a, b, &r)) fail(std::string(what) + ": arithmetic overflow");
  return r;
}

inline std::uint64_t checked_mul(std::uint64_t a, std::uint64_t b, std::string_view what) {
  std::uint64_t r = 0;
  if (__builtin_mul_overflow(a, b, &r)) fail(std::string(what) + ": arithmetic overflow");
  return r;
}

class Reader {
 public:
  Reader(std::span<const std::byte> data, Endian endian) : data_(data), endian_(endian) {}

  std::uint64_t size() const { return data_.size(); }
  Endian endian() const { return endian_; }
  void set_endian(Endian e) { endian_ = e; }

  bool has(std::uint64_t off, std::uint64_t len) const {
    return off <= data_.size() && len <= data_.size() - off;
  }

  void require(std::uint64_t off, std::uint64_t len, std::string_view what) const {
    if (!has(off, len))
      fail(std::string(what) + " out of bounds (offset " + hex(off) + ", size " + hex(len) +
           ", file size " + hex(data_.size()) + ")");
  }

  std::span<const std::byte> bytes(std::uint64_t off, std::uint64_t len, std::string_view what) const {
    require(off, len, what);
    return data_.subspan(static_cast<std::size_t>(off), static_cast<std::size_t>(len));
  }

  std::uint8_t u8(std::uint64_t off, std::string_view what = "read") const {
    return static_cast<std::uint8_t>(read_uint(off, 1, what));
  }
  std::uint16_t u16(std::uint64_t off, std::string_view what = "read") const {
    return static_cast<std::uint16_t>(read_uint(off, 2, what));
  }
  std::uint32_t u32(std::uint64_t off, std::string_view what = "read") const {
    return static_cast<std::uint32_t>(read_uint(off, 4, what));
  }
  std::uint64_t u64(std::uint64_t off, std::string_view what = "read") const {
    return read_uint(off, 8, what);
  }
  // Reads a 4- or 8-byte word, as ELF/PE fields that depend on the class.
  std::uint64_t word(std::uint64_t off, bool wide, std::string_view what = "read") const {
    return read_uint(off, wide ? 8 : 4, what);
  }

  // NUL-terminated string starting at `off`, which must end inside the
  // buffer and within `max_len` bytes.
  std::string cstring(std::uint64_t off, std::uint64_t max_len, std::string_view what) const {
    require(off, 0, what);
    std::uint64_t avail = data_.size() - off;
    std::uint64_t limit = avail < max_len ? avail : max_len;
    for (std::uint64_t i = 0; i < limit; ++i) {
      if (data_[static_cast<std::size_t>(off + i)] == std::byte{0})
        return std::string(reinterpret_cast<const char *>(data_.data() + off), static_cast<std::size_t>(i));
    }
    fail(std::string(what) + ": unterminated string at offset " + hex(off));
  }

 private:
  std::uint64_t read_uint(std::uint64_t off, unsigned n, std::string_view what) const {
    require(off, n, what);
    std::uint64_t v = 0;
    const std::byte *p = data_.data() + off;
    for (unsigned i = 0; i < n; ++i) {
      unsigned idx = endian_ == Endian::little ? n - 1 - i : i;
      v = (v << 8) | static_cast<std::uint8_t>(p[idx]);
    }
    return v;
  }

  std::span<const std::byte> data_;
  Endian endian_;
};

}  // namespace revkit::loader::detail
