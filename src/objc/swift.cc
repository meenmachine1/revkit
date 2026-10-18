// Swift type metadata (Ghidra's SwiftTypeMetadata): the type context
// descriptors __swift5_types lists, with their names, parents, metadata
// accessors and fields, and non-generic classes' vtables.
//
// The class vtable reading follows rea's src/native/AppleSwiftVtables.ts
// (github.com/morluto/rea, MIT, Copyright (c) 2026 morluto).

#include "revkit/objc/objc.h"

#include "reader.h"

namespace revkit::objc {

namespace {

using detail::Reader;

constexpr std::uint32_t kMaxTypes = 1 << 18;
constexpr std::uint32_t kMaxFields = 1 << 12;
constexpr std::uint32_t kMaxVtable = 20000;

const char *kind_name(std::uint32_t kind) {
  switch (kind) {
    case 3: return "protocol";
    case 16: return "class";
    case 17: return "struct";
    case 18: return "enum";
    default: return nullptr;
  }
}

// A relative pointer whose low bit says it is indirect (through a pointer
// slot): what it points to.
std::optional<std::uint64_t> indirectable(const Reader &r, std::uint64_t field) {
  auto v = r.i32(field);
  if (!v || *v == 0) return std::nullopt;
  const std::uint64_t to = field + static_cast<std::uint64_t>(static_cast<std::int64_t>(*v & ~1));
  if ((*v & 1) == 0) return to;
  auto p = r.ptr(to);
  if (!p || *p == 0) return std::nullopt;
  return *p;
}

}  // namespace

void scan_swift(const loader::Image &image, Metadata &out) {
  Reader r(image);
  for (const loader::Section *s : r.sections("__swift5_types")) {
    for (std::uint64_t e = s->addr; e + 4 <= s->addr + s->size && out.swift_types.size() < kMaxTypes; e += 4) {
      auto v = r.i32(e);
      if (!v || *v == 0) continue;
      // TypeMetadataRecord: an offset with the reference's kind in its low
      // two bits (0 direct, 1 indirect descriptor; 2 and 3 Objective-C).
      const unsigned refkind = static_cast<unsigned>(*v) & 3;
      if (refkind > 1) continue;
      std::uint64_t d = e + static_cast<std::uint64_t>(static_cast<std::int64_t>(*v & ~3));
      if (refkind == 1) {
        auto p = r.ptr(d);
        if (!p || *p == 0) continue;
        d = *p;
      }
      auto flags = r.u32(d);
      if (!flags) continue;
      const char *kind = kind_name(*flags & 0x1f);
      if (kind == nullptr || std::string_view(kind) == "protocol") continue;
      SwiftType t;
      t.kind = kind;
      t.descriptor = d;
      if (auto n = r.relative(d + 8)) t.name = r.cstr(*n, 1024).value_or("");
      if (t.name.empty()) continue;
      if (auto parent = indirectable(r, d + 4)) {
        auto pf = r.u32(*parent);
        // A module, or an enclosing type, names the parent.
        if (pf && ((*pf & 0x1f) == 0 || kind_name(*pf & 0x1f) != nullptr))
          if (auto pn = r.relative(*parent + 8)) t.parent = r.cstr(*pn, 1024).value_or("");
      }
      if (auto acc = r.relative(d + 12); acc && r.executable(*acc)) t.accessor = *acc;
      if (auto fd = r.relative(d + 16)) {
        t.field_descriptor = *fd;
        auto rec = r.u32(*fd + 8), count = r.u32(*fd + 12);
        const std::uint32_t size = rec ? *rec >> 16 : 0;
        if (count && size >= 12 && *count <= kMaxFields)
          for (std::uint32_t i = 0; i < *count; ++i)
            if (auto name = r.relative(*fd + 16 + std::uint64_t{i} * size + 8))
              t.fields.push_back(r.cstr(*name, 1024).value_or(""));
      }
      // A class's vtable (rea's decodeSwiftClassVtables): not generic
      // (0x80), no resilient superclass (kind-specific 0x2000), with one
      // (0x8000); after the 44-byte descriptor and its metadata
      // initialization (singleton: 12 bytes, foreign: 4), the header's
      // offset and size, then method descriptors of flags and an
      // implementation offset.
      if (t.kind == "class" && (*flags & 0x80) == 0) {
        const std::uint32_t specific = *flags >> 16;
        const std::uint32_t init = specific & 3;
        if ((specific & 0x2000) == 0 && (specific & 0x8000) != 0 && init != 3) {
          const std::uint64_t header = d + 44 + (init == 1 ? 12 : init == 2 ? 4 : 0);
          auto offset = r.u32(header), count = r.u32(header + 4), positive = r.u32(d + 28);
          if (offset && count && positive && *count <= kMaxVtable && std::uint64_t{*offset} + *count <= *positive)
            for (std::uint32_t i = 0; i < *count; ++i) {
              const std::uint64_t m = header + 8 + std::uint64_t{i} * 8;
              auto mflags = r.u32(m);
              auto impl = r.relative(m + 4);
              // Synchronous methods (async ones point at async descriptors).
              const bool sync = mflags && (*mflags & 0x40) == 0 && (*mflags & 15) <= 3;
              t.vtable.push_back(sync && impl && r.executable(*impl) ? *impl : 0);
            }
        }
      }
      out.swift_types.push_back(std::move(t));
    }
  }
}

}  // namespace revkit::objc
