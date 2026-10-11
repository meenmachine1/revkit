// A bounds-checked reader over one section's bytes. Every read checks the
// remaining length and throws FormatError instead of reading past the end.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>

namespace revkit::debuginfo {

class FormatError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

class Cursor {
 public:
  Cursor(std::span<const std::uint8_t> data, bool big_endian, std::size_t pos = 0)
      : data_(data), big_endian_(big_endian), pos_(pos) {
    if (pos > data.size()) throw FormatError("offset past end of section");
  }

  std::size_t pos() const { return pos_; }
  std::size_t size() const { return data_.size(); }
  std::size_t remaining() const { return data_.size() - pos_; }
  bool at_end() const { return pos_ >= data_.size(); }
  void seek(std::uint64_t pos) {
    if (pos > data_.size()) throw FormatError("seek past end of section");
    pos_ = std::size_t(pos);
  }
  void skip(std::uint64_t n) {
    need(n);
    pos_ += std::size_t(n);
  }

  std::uint8_t u8() {
    need(1);
    return data_[pos_++];
  }
  std::uint16_t u16() { return std::uint16_t(un(2)); }
  std::uint32_t u32() { return std::uint32_t(un(4)); }
  std::uint64_t u64() { return un(8); }
  // An unsigned integer of 1 to 8 bytes in the section's byte order.
  std::uint64_t un(unsigned n) {
    if (n == 0 || n > 8) throw FormatError("bad integer size " + std::to_string(n));
    need(n);
    std::uint64_t v = 0;
    for (unsigned i = 0; i < n; ++i) {
      std::uint64_t b = data_[pos_ + i];
      v |= big_endian_ ? b << (8 * (n - 1 - i)) : b << (8 * i);
    }
    pos_ += n;
    return v;
  }
  std::uint64_t uleb() {
    std::uint64_t v = 0;
    for (unsigned shift = 0;; shift += 7) {
      std::uint8_t b = u8();
      if (shift < 64) v |= std::uint64_t(b & 0x7f) << shift;
      if (!(b & 0x80)) return v;
    }
  }
  std::int64_t sleb() {
    std::uint64_t v = 0;
    unsigned shift = 0;
    std::uint8_t b;
    do {
      b = u8();
      if (shift < 64) v |= std::uint64_t(b & 0x7f) << shift;
      shift += 7;
    } while (b & 0x80);
    if (shift < 64 && (b & 0x40)) v |= ~std::uint64_t(0) << shift;
    return std::int64_t(v);
  }
  std::string_view cstr() {
    std::size_t end = pos_;
    while (end < data_.size() && data_[end] != 0) ++end;
    if (end >= data_.size()) throw FormatError("unterminated string");
    std::string_view s(reinterpret_cast<const char *>(data_.data() + pos_), end - pos_);
    pos_ = end + 1;
    return s;
  }
  std::span<const std::uint8_t> bytes(std::uint64_t n) {
    need(n);
    auto s = data_.subspan(pos_, std::size_t(n));
    pos_ += std::size_t(n);
    return s;
  }

 private:
  void need(std::uint64_t n) const {
    if (n > data_.size() - pos_) throw FormatError("read past end of section");
  }

  std::span<const std::uint8_t> data_;
  bool big_endian_;
  std::size_t pos_;
};

}  // namespace revkit::debuginfo
