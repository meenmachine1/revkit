// Bounds-checked reads of a loaded image's memory by virtual address.
#pragma once

#include "revkit/loader/image.hh"

#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

namespace revkit::msvc::detail {

class View {
 public:
  explicit View(const loader::Image &image)
      : image_(image), pointer_(image.bits / 8 == 4 ? 4 : 8), base_(image.image_base) {}

  const loader::Image &image() const { return image_; }
  unsigned pointer() const { return pointer_; }
  std::uint64_t base() const { return base_; }
  bool wide() const { return pointer_ == 8; }

  // Every byte of [a, a + n) is mapped and backed by the file (or zero fill
  // of an initialized region).
  bool mapped(std::uint64_t a, std::uint64_t n = 1) const {
    if (n == 0) return true;
    if (a + (n - 1) < a) return false;
    for (;;) {
      const loader::Region *r = image_.memory.find(a);
      if (r == nullptr) return false;
      const std::uint64_t last = r->last();
      if (a + (n - 1) <= last) return true;
      n -= last - a + 1;
      a = last + 1;
    }
  }
  bool executable(std::uint64_t a) const {
    const loader::Region *r = image_.memory.find(a);
    return r != nullptr && r->perms.exec;
  }
  bool writable(std::uint64_t a) const {
    const loader::Region *r = image_.memory.find(a);
    return r != nullptr && r->perms.write;
  }

  std::optional<std::uint64_t> uint(std::uint64_t a, unsigned n) const {
    if (n == 0 || n > 8 || a + (n - 1) < a) return std::nullopt;
    const loader::Region *r = image_.memory.find(a);
    if (r == nullptr || a + (n - 1) > r->last()) return std::nullopt;
    std::byte b[8]{};
    if (image_.memory.read(a, std::span<std::byte>(b, n)) != n) return std::nullopt;
    std::uint64_t v = 0;
    for (unsigned i = 0; i < n; ++i) v |= std::uint64_t{static_cast<std::uint8_t>(b[i])} << (8 * i);
    return v;
  }
  std::optional<std::uint32_t> u32(std::uint64_t a) const {
    auto v = uint(a, 4);
    if (!v) return std::nullopt;
    return static_cast<std::uint32_t>(*v);
  }
  std::optional<std::uint16_t> u16(std::uint64_t a) const {
    auto v = uint(a, 2);
    if (!v) return std::nullopt;
    return static_cast<std::uint16_t>(*v);
  }
  std::optional<std::int32_t> i32(std::uint64_t a) const {
    auto v = u32(a);
    if (!v) return std::nullopt;
    return static_cast<std::int32_t>(*v);
  }
  std::optional<std::uint64_t> ptr(std::uint64_t a) const { return uint(a, pointer_); }
  // An image-relative offset (x64 RTTI, exception data) as an address.
  std::uint64_t rva(std::uint32_t v) const {
    const std::uint64_t a = base_ + v;
    return wide() ? a : (a & 0xffffffffULL);
  }
  // A reference field: an image-relative 32-bit offset on 64-bit images,
  // an absolute pointer on 32-bit ones (RTTI's convention).
  std::optional<std::uint64_t> ref(std::uint64_t a) const {
    if (wide()) {
      auto v = u32(a);
      if (!v) return std::nullopt;
      return *v == 0 ? 0 : rva(*v);
    }
    return ptr(a);
  }
  unsigned ref_size() const { return 4; }

  // A NUL-terminated string of at most `max` bytes before the NUL.
  std::optional<std::string> cstring(std::uint64_t a, std::size_t max) const {
    std::string out;
    for (std::size_t i = 0; i <= max; ++i) {
      auto c = uint(a + i, 1);
      if (!c) return std::nullopt;
      if (*c == 0) return out;
      out.push_back(static_cast<char>(*c));
    }
    return std::nullopt;
  }

  // The bytes of an initialized block, for scanning.
  std::vector<std::uint8_t> block_bytes(const loader::Block &b) const {
    std::vector<std::uint8_t> out(static_cast<std::size_t>(b.size));
    if (!out.empty())
      image_.memory.read(b.start, std::span<std::byte>(reinterpret_cast<std::byte *>(out.data()), out.size()));
    return out;
  }

 private:
  const loader::Image &image_;
  unsigned pointer_;
  std::uint64_t base_;
};

// Blocks worth scanning for data: initialized, readable, not executable,
// at most 256 MiB each.
inline std::vector<const loader::Block *> data_blocks(const loader::Image &image) {
  std::vector<const loader::Block *> out;
  for (const loader::Block &b : image.blocks)
    if (b.initialized && b.perms.read && !b.perms.exec && b.size != 0 && b.size <= (256u << 20)) out.push_back(&b);
  return out;
}

}  // namespace revkit::msvc::detail
