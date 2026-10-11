// Shared by the markup passes (RTTI, PE structures, exception data).
#pragma once

#include "revkit/msvc/msvc.h"

#include "view.h"

#include <string>
#include <utility>
#include <vector>

namespace revkit::msvc::detail {

// Builds the markup: types interned once by name, data kept disjoint.
class Builder {
 public:
  Builder(const loader::Image &image, Markup &out) : v(image), out(out) {}

  View v;
  Markup &out;
  std::string pass = "msvc";  // what the defs made now are found by

  types::TypeStore &store() { return out.store; }
  unsigned ptr() const { return v.pointer(); }

  // Scalars as the listing spells them.
  types::TypeId u8() { return store().int_type(1, false, types::IntRank::Char); }
  types::TypeId u16() { return store().int_type(2, false, types::IntRank::Short); }
  types::TypeId u32() { return store().int_type(4, false, types::IntRank::Int); }
  types::TypeId i32() { return store().int_type(4, true, types::IntRank::Int); }
  types::TypeId u64() { return store().int_type(8, false, types::IntRank::LongLong); }
  types::TypeId word() { return typedef_("WORD", u16()); }
  types::TypeId dword() { return typedef_("DWORD", u32()); }
  types::TypeId byte() { return typedef_("BYTE", u8()); }
  types::TypeId ulonglong() { return typedef_("ULONGLONG", u64()); }
  types::TypeId ibo32() { return typedef_("ImageBaseOffset32", u32()); }
  types::TypeId voidp() { return store().pointer_to(store().void_type(), ptr()); }
  types::TypeId pointer(types::TypeId to) { return store().pointer_to(to, ptr()); }
  types::TypeId chars(std::uint64_t n) {
    return store().array_of(store().int_type(1, true, types::IntRank::PlainChar), n);
  }
  types::TypeId typedef_(const std::string &name, types::TypeId target) { return store().typedef_of(name, target); }
  // A reference field: a pointer to `to` on 32-bit images, ImageBaseOffset32
  // on 64-bit ones.
  types::TypeId ref(types::TypeId to) { return v.wide() ? ibo32() : pointer(to); }

  struct F {
    std::string name;
    types::TypeId type;
  };
  // A struct of consecutive fields (natural layout, no padding unless the
  // fields' own alignment asks).
  types::TypeId struct_(const std::string &name, const std::vector<F> &fields,
                        types::AggregateKind kind = types::AggregateKind::Struct, std::uint64_t min_size = 0,
                        bool packed = false) {
    types::AggregateType a;
    a.kind = kind;
    a.name = name;
    a.packed = packed;
    std::uint64_t at = 0;
    std::uint32_t align = 1;
    for (const F &f : fields) {
      const std::uint32_t al = packed ? 1 : std::max<std::uint32_t>(1, store().align_of(f.type));
      at = (at + al - 1) / al * al;
      a.fields.push_back({f.name, f.type, at * 8, 0});
      at += store().size_of(f.type);
      align = std::max(align, al);
    }
    at = (at + align - 1) / align * align;
    a.size = std::max(at, min_size);
    return store().intern(types::Type(std::move(a)));
  }

  // Data, unless it overlaps data already laid down (the first wins).
  bool data(std::uint64_t address, types::TypeId type, std::string name = {}, std::uint64_t count = 0,
            bool collapsed = false) {
    const std::uint64_t size = store().size_of(type) * (count == 0 ? 1 : count);
    if (size == 0 || !v.mapped(address, size)) return false;
    if (!claim(address, size)) return false;
    out.data.push_back({address, type, count, std::move(name), collapsed, false, pass});
    return true;
  }
  // A NUL-terminated string of `length` bytes (the NUL included).
  bool string(std::uint64_t address, std::uint64_t length, std::string name = {}) {
    if (length == 0 || !v.mapped(address, length) || !claim(address, length)) return false;
    out.data.push_back({address, chars(length), 0, std::move(name), true, true, pass});
    return true;
  }
  void label(std::uint64_t address, std::string name) { out.labels.push_back({address, std::move(name), pass}); }
  void function(FunctionDef f) {
    f.pass = pass;
    out.functions.push_back(std::move(f));
  }

  bool claim(std::uint64_t address, std::uint64_t size);

 private:
  std::vector<std::pair<std::uint64_t, std::uint64_t>> claimed_;  // [first, last], sorted
};

// The RTTI pass (rtti_markup.cc).
void rtti_markup(Builder &b, const Rtti &rtti, const MarkupOptions &options);
// The PE structures and exception data (pe_markup.cc).
void pe_markup(Builder &b, const MarkupOptions &options);

}  // namespace revkit::msvc::detail
