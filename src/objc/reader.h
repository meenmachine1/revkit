// Reads a Mach-O image's memory as dyld leaves it: a rebased pointer at
// its target (a chained fixup's encoding decoded), a bound one as the
// symbol it names. Every read is bounds-checked.
#pragma once

#include "revkit/loader/image.hh"

#include <algorithm>
#include <cstdint>
#include <initializer_list>
#include <span>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace revkit::objc::detail {

class Reader {
 public:
  explicit Reader(const loader::Image &image) : image_(image), ptr_(image.bits == 32 ? 4 : 8) {
    for (const loader::Relocation &r : image.relocations) {
      if (!r.symbol.empty()) bound_[r.address] = r.symbol;
      else if (r.kind == loader::RelocationKind::relative && r.target) rebased_[r.address] = *r.target;
    }
  }

  const loader::Image &image() const { return image_; }
  unsigned pointer() const { return ptr_; }

  bool mapped(std::uint64_t a, std::uint64_t n = 1) const {
    if (n == 0) return true;
    if (a + (n - 1) < a) return false;
    for (;;) {
      const loader::Region *r = image_.memory.find(a);
      if (r == nullptr) return false;
      if (a + (n - 1) <= r->last()) return true;
      n -= r->last() - a + 1;
      a = r->last() + 1;
    }
  }
  bool executable(std::uint64_t a) const {
    const loader::Region *r = image_.memory.find(a);
    return r != nullptr && r->perms.exec;
  }

  std::optional<std::uint64_t> uint(std::uint64_t a, unsigned n) const {
    if (n == 0 || n > 8 || !mapped(a, n)) return std::nullopt;
    std::byte b[8]{};
    if (image_.memory.read(a, std::span<std::byte>(b, n)) != n) return std::nullopt;
    std::uint64_t v = 0;
    for (unsigned i = 0; i < n; ++i)
      v |= std::uint64_t{static_cast<std::uint8_t>(b[image_.endian == loader::Endian::little ? i : n - 1 - i])} << (8 * i);
    return v;
  }
  std::optional<std::uint32_t> u32(std::uint64_t a) const {
    auto v = uint(a, 4);
    return v ? std::optional<std::uint32_t>(static_cast<std::uint32_t>(*v)) : std::nullopt;
  }
  std::optional<std::int32_t> i32(std::uint64_t a) const {
    auto v = u32(a);
    return v ? std::optional<std::int32_t>(static_cast<std::int32_t>(*v)) : std::nullopt;
  }
  // A pointer-sized word as dyld leaves it: 0 for a bind (bound(a) names
  // its symbol), a rebase's target, else the stored word.
  std::optional<std::uint64_t> ptr(std::uint64_t a) const {
    if (bound_.contains(a)) return mapped(a, ptr_) ? std::optional<std::uint64_t>(0) : std::nullopt;
    if (auto it = rebased_.find(a); it != rebased_.end()) return it->second;
    return uint(a, ptr_);
  }
  // The symbol a bind at `a` names ("_OBJC_CLASS_$_NSObject"), or "".
  std::string bound(std::uint64_t a) const {
    auto it = bound_.find(a);
    return it == bound_.end() ? std::string() : it->second;
  }
  // A 32-bit offset from `a` to what it points to (Swift and relative
  // method lists); nullopt for 0.
  std::optional<std::uint64_t> relative(std::uint64_t a) const {
    auto v = i32(a);
    if (!v || *v == 0) return std::nullopt;
    return a + static_cast<std::uint64_t>(static_cast<std::int64_t>(*v));
  }
  // A NUL-terminated string of at most `max` bytes, or nullopt.
  std::optional<std::string> cstr(std::uint64_t a, std::size_t max = 4096) const {
    std::string s;
    std::byte b[64];
    for (std::uint64_t at = a; s.size() < max;) {
      const loader::Region *r = image_.memory.find(at);
      if (r == nullptr) return std::nullopt;
      const std::uint64_t n = std::min<std::uint64_t>({sizeof b, r->last() - at + 1, max - s.size()});
      image_.memory.read(at, std::span<std::byte>(b, static_cast<std::size_t>(n)));
      for (std::uint64_t i = 0; i < n; ++i) {
        if (b[i] == std::byte{0}) return s;
        s.push_back(static_cast<char>(b[i]));
      }
      at += n;
    }
    return std::nullopt;
  }

  // The first section named `name` in any segment of `segments`.
  const loader::Section *section(std::string_view name, std::initializer_list<std::string_view> segments) const {
    for (const loader::Section &s : image_.sections)
      if (s.name == name)
        for (std::string_view seg : segments)
          if (s.segment == seg && s.size != 0) return &s;
    return nullptr;
  }
  std::vector<const loader::Section *> sections(std::string_view name) const {
    std::vector<const loader::Section *> out;
    for (const loader::Section &s : image_.sections)
      if (s.name == name && s.size != 0) out.push_back(&s);
    return out;
  }

 private:
  const loader::Image &image_;
  unsigned ptr_;
  std::unordered_map<std::uint64_t, std::string> bound_;
  std::unordered_map<std::uint64_t, std::uint64_t> rebased_;
};

}  // namespace revkit::objc::detail
