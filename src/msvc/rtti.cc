// MSVC RTTI: finding the run-time type information structures and the
// vftables their CompleteObjectLocators lead to.
//
// Layouts (rttidata.h; "ref" is an absolute pointer on 32-bit images and an
// image-relative 32-bit offset on 64-bit ones):
//
//   TypeDescriptor           { void *pVFTable; void *spare; char name[]; }
//   RTTICompleteObjectLocator{ u32 signature (0, or 1 when image-relative);
//                              u32 offset; u32 cdOffset; ref pTypeDescriptor;
//                              ref pClassDescriptor; [64-bit: ref pSelf] }
//   RTTIClassHierarchyDescriptor { u32 signature; u32 attributes;
//                              u32 numBaseClasses; ref pBaseClassArray }
//   RTTIBaseClassArray       ref[numBaseClasses]
//   RTTIBaseClassDescriptor  { ref pTypeDescriptor; u32 numContainedBases;
//                              PMD { i32 mdisp, pdisp, vdisp }; u32 attributes;
//                              ref pClassDescriptor }
//   vftable                  the locator's address in the slot before it,
//                            then pointers to code
//
// The search follows Ghidra's RTTI analyzer: TypeDescriptors by their
// ".?AV"/".?AU" names, locators by a signature and a TypeDescriptor that
// was found (and, on 64-bit images, pSelf pointing back), hierarchies and
// base classes from the locators and their arrays, vftables by the slots
// that hold a locator's address.

#include "revkit/msvc/msvc.h"

#include "view.h"

#include "revkit/demangle/demangle.h"

#include <algorithm>
#include <cstring>
#include <set>
#include <unordered_map>
#include <unordered_set>

namespace revkit::msvc {

using detail::View;

namespace {

constexpr std::size_t kMaxNameLength = 4096;
constexpr std::uint32_t kMaxBases = 4096;
constexpr std::size_t kMaxVftableEntries = 4096;

// A TypeDescriptor name of a class or struct: ".?AV" or ".?AU", printable,
// ending in "@@".
bool plausible_class_name(const std::string &n) {
  if (n.size() < 6 || !(n.starts_with(".?AV") || n.starts_with(".?AU"))) return false;
  if (!n.ends_with("@@")) return false;
  for (unsigned char c : n)
    if (c < 0x21 || c > 0x7e) return false;
  return true;
}

std::string replace_all(std::string s, std::string_view from, std::string_view to) {
  for (std::size_t at = 0; (at = s.find(from, at)) != std::string::npos; at += to.size()) s.replace(at, from.size(), to);
  return s;
}

}  // namespace

std::optional<std::string> class_name(std::string_view td_name) {
  std::optional<std::string> d = demangle::demangle_microsoft(td_name);
  if (!d || d->empty()) return std::nullopt;
  std::string s = *d;
  // LLVM spells a type descriptor's name "struct geo::Rect `RTTI Type
  // Descriptor Name'".
  for (std::string_view suffix : {std::string_view(" `RTTI Type Descriptor Name'")})
    if (s.ends_with(suffix)) s.resize(s.size() - suffix.size());
  // "class geo::Rect", "struct std::pair<int,class std::basic_string<...> >":
  // the qualified name as one token, as the demangler analysis names
  // classes (no tags, no space after a comma or before '>', other spaces
  // as '_').
  for (const char *tag : {"class ", "struct ", "union ", "enum "}) s = replace_all(std::move(s), tag, "");
  s = replace_all(std::move(s), ", ", ",");
  s = replace_all(std::move(s), " >", ">");
  for (char &c : s)
    if (c == ' ') c = '_';
  return s;
}

std::vector<std::size_t> ClassInfo::direct_bases() const {
  std::vector<std::size_t> out;
  if (bases.empty()) return out;
  // A preorder walk: the root's children start at 1, each followed by its
  // own subtree.
  std::size_t end = std::min<std::size_t>(bases.size(), 1 + std::size_t{bases[0].contained_bases});
  for (std::size_t i = 1; i < end;) {
    out.push_back(i);
    i += 1 + std::size_t{bases[i].contained_bases};
  }
  return out;
}

const ClassInfo *Rtti::by_type_descriptor(std::uint64_t td) const {
  auto i = index_of(td);
  return i ? &classes[*i] : nullptr;
}

std::optional<std::size_t> Rtti::index_of(std::uint64_t td) const {
  auto it = std::lower_bound(classes.begin(), classes.end(), td,
                             [](const ClassInfo &c, std::uint64_t a) { return c.type_descriptor < a; });
  if (it == classes.end() || it->type_descriptor != td) return std::nullopt;
  return static_cast<std::size_t>(it - classes.begin());
}

namespace {

class Scanner {
 public:
  explicit Scanner(const loader::Image &image) : v_(image) {
    out_.pointer = v_.pointer();
    out_.image_relative = v_.wide();
  }

  Rtti run() {
    if (v_.image().format != loader::Format::pe) return std::move(out_);
    blocks_ = detail::data_blocks(v_.image());
    for (const loader::Block *b : blocks_) bytes_.push_back(v_.block_bytes(*b));
    type_descriptors();
    if (out_.classes.empty()) return std::move(out_);
    locators();
    hierarchies();
    vftables();
    return std::move(out_);
  }

 private:
  void type_descriptors() {
    const unsigned p = v_.pointer();
    for (std::size_t bi = 0; bi < blocks_.size(); ++bi) {
      const loader::Block &b = *blocks_[bi];
      const std::vector<std::uint8_t> &bytes = bytes_[bi];
      const std::uint8_t *data = bytes.data();
      const std::size_t n = bytes.size();
      for (std::size_t off = 2 * p; off + 4 <= n;) {
        const void *hit = std::memchr(data + off, '.', n - off);
        if (hit == nullptr) break;
        off = static_cast<std::size_t>(static_cast<const std::uint8_t *>(hit) - data);
        const std::size_t at = off++;
        if (at + 4 > n || data[at + 1] != '?' || data[at + 2] != 'A') continue;
        const std::uint64_t td = b.start + at - 2 * p;
        if (td % p != 0) continue;
        auto spare = v_.ptr(td + p);
        auto vft = v_.ptr(td);
        if (!spare || *spare != 0 || !vft || (*vft != 0 && !v_.mapped(*vft))) continue;
        auto name = v_.cstring(td + 2 * p, kMaxNameLength);
        if (!name || !plausible_class_name(*name)) continue;
        auto cn = class_name(*name);
        if (!cn) continue;
        ClassInfo c;
        c.name = *cn;
        c.mangled = *name;
        c.is_struct = name->starts_with(".?AU");
        c.type_descriptor = td;
        c.name_length = static_cast<std::uint32_t>(name->size() + 1);
        out_.classes.push_back(std::move(c));
        off = at + name->size();
      }
    }
    std::sort(out_.classes.begin(), out_.classes.end(),
              [](const ClassInfo &a, const ClassInfo &b) { return a.type_descriptor < b.type_descriptor; });
    out_.classes.erase(std::unique(out_.classes.begin(), out_.classes.end(),
                                   [](const ClassInfo &a, const ClassInfo &b) {
                                     return a.type_descriptor == b.type_descriptor;
                                   }),
                       out_.classes.end());
  }

  std::uint64_t locator_size() const { return v_.wide() ? 24 : 20; }

  void locators() {
    const bool wide = v_.wide();
    for (std::size_t bi = 0; bi < blocks_.size(); ++bi) {
      const loader::Block &b = *blocks_[bi];
      const std::vector<std::uint8_t> &bytes = bytes_[bi];
      const std::uint64_t first = (b.start + 3) & ~std::uint64_t{3};
      for (std::uint64_t a = first; a + locator_size() <= b.start + bytes.size(); a += 4) {
        const std::size_t off = static_cast<std::size_t>(a - b.start);
        std::uint32_t sig = 0;
        std::memcpy(&sig, bytes.data() + off, 4);
        if (sig != (wide ? 1u : 0u)) continue;
        auto td = v_.ref(a + 12);
        if (!td || !out_.index_of(*td)) continue;
        if (wide) {
          auto self = v_.ref(a + 20);
          if (!self || *self != a) continue;
        }
        auto chd = v_.ref(a + 16);
        if (!chd || !valid_hierarchy(*chd, *td)) continue;
        auto offset = v_.u32(a + 4), cd_offset = v_.u32(a + 8);
        if (!offset || !cd_offset) continue;
        Locator l;
        l.address = a;
        l.signature = sig;
        l.offset = *offset;
        l.cd_offset = *cd_offset;
        l.type_descriptor = *td;
        l.hierarchy = *chd;
        l.cls = *out_.index_of(*td);
        out_.locators.push_back(l);
      }
    }
  }

  // A ClassHierarchyDescriptor whose array starts with the class itself.
  bool valid_hierarchy(std::uint64_t chd, std::uint64_t td) const {
    if (chd == 0 || !v_.mapped(chd, 16)) return false;
    auto sig = v_.u32(chd);
    auto count = v_.u32(chd + 8);
    auto bca = v_.ref(chd + 12);
    if (!sig || *sig != 0 || !count || *count == 0 || *count > kMaxBases || !bca || *bca == 0) return false;
    auto bcd0 = v_.ref(*bca);
    if (!bcd0 || *bcd0 == 0) return false;
    auto td0 = v_.ref(*bcd0);
    return td0 && *td0 == td;
  }

  void hierarchies() {
    // Each class's hierarchy: its locators', else what a base class
    // descriptor of it points to.
    for (const Locator &l : out_.locators) {
      ClassInfo &c = out_.classes[l.cls];
      if (c.hierarchy == 0) c.hierarchy = l.hierarchy;
    }
    // Read every hierarchy reachable, including bases' own. Each class's
    // once: one that fails stays without bases, and isn't re-read per pass.
    std::vector<char> tried(out_.classes.size());
    for (bool changed = true; changed;) {
      changed = false;
      for (std::size_t i = 0; i < out_.classes.size(); ++i) {
        ClassInfo &c = out_.classes[i];
        if (c.hierarchy == 0 || !c.bases.empty() || tried[i]) continue;
        tried[i] = 1;
        read_hierarchy(c);
        for (const BaseClass &bc : out_.classes[i].bases) {
          if (bc.hierarchy == 0) continue;
          if (auto j = out_.index_of(bc.type_descriptor)) {
            ClassInfo &base = out_.classes[*j];
            if (base.hierarchy == 0 && valid_hierarchy(bc.hierarchy, base.type_descriptor)) {
              base.hierarchy = bc.hierarchy;
              changed = true;
            }
          }
        }
      }
    }
  }

  void read_hierarchy(ClassInfo &c) {
    auto attrs = v_.u32(c.hierarchy + 4);
    auto count = v_.u32(c.hierarchy + 8);
    auto bca = v_.ref(c.hierarchy + 12);
    if (!attrs || !count || !bca) return;
    c.hierarchy_attributes = *attrs;
    c.base_array = *bca;
    const unsigned rs = v_.wide() ? 4 : v_.pointer();
    std::vector<BaseClass> bases;
    for (std::uint32_t i = 0; i < *count; ++i) {
      auto bcd = v_.ref(*bca + std::uint64_t{i} * rs);
      if (!bcd || *bcd == 0 || !v_.mapped(*bcd, 7 * 4)) return;
      BaseClass bc;
      bc.descriptor = *bcd;
      auto td = v_.ref(*bcd);
      if (!td) return;
      bc.type_descriptor = *td;
      if (const ClassInfo *k = out_.by_type_descriptor(*td)) bc.name = k->name;
      // mapped() allows a descriptor across two adjacent regions, which
      // one read doesn't: each field is checked.
      auto contained = v_.u32(*bcd + 4), attributes = v_.u32(*bcd + 20);
      auto mdisp = v_.i32(*bcd + 8), pdisp = v_.i32(*bcd + 12), vdisp = v_.i32(*bcd + 16);
      if (!contained || !attributes || !mdisp || !pdisp || !vdisp) return;
      bc.contained_bases = *contained;
      bc.mdisp = *mdisp;
      bc.pdisp = *pdisp;
      bc.vdisp = *vdisp;
      bc.attributes = *attributes;
      if ((bc.attributes & kBcdHasPchd) != 0)
        if (auto h = v_.ref(*bcd + 24)) bc.hierarchy = *h;
      if (bc.contained_bases >= *count) return;  // a subtree larger than the array
      bases.push_back(std::move(bc));
    }
    if (bases.empty() || bases[0].type_descriptor != c.type_descriptor) return;
    // Depths from the subtree sizes.
    std::vector<std::size_t> ends;  // open subtrees' ends
    for (std::size_t i = 0; i < bases.size(); ++i) {
      while (!ends.empty() && ends.back() <= i) ends.pop_back();
      bases[i].depth = static_cast<std::uint32_t>(ends.size());
      ends.push_back(i + 1 + bases[i].contained_bases);
    }
    c.bases = std::move(bases);
  }

  void vftables() {
    std::unordered_map<std::uint64_t, std::size_t> by_locator;
    for (std::size_t i = 0; i < out_.locators.size(); ++i) by_locator.emplace(out_.locators[i].address, i);
    const unsigned p = v_.pointer();
    // Slots that hold a locator's address: each starts a vftable after it.
    std::vector<std::pair<std::uint64_t, std::size_t>> metas;
    for (std::size_t bi = 0; bi < blocks_.size(); ++bi) {
      const loader::Block &b = *blocks_[bi];
      const std::vector<std::uint8_t> &bytes = bytes_[bi];
      const std::uint64_t first = (b.start + (p - 1)) & ~std::uint64_t{p - 1};
      for (std::uint64_t a = first; a + p <= b.start + bytes.size(); a += p) {
        std::uint64_t value = 0;
        std::memcpy(&value, bytes.data() + (a - b.start), p);
        auto it = by_locator.find(value);
        if (it != by_locator.end()) metas.emplace_back(a, it->second);
      }
    }
    std::unordered_set<std::uint64_t> meta_slots;
    for (const auto &[a, _] : metas) meta_slots.insert(a);
    for (const auto &[meta, li] : metas) {
      const Locator &l = out_.locators[li];
      Vftable t;
      t.meta = meta;
      t.address = meta + p;
      t.locator = l.address;
      t.cls = l.cls;
      t.offset = l.offset;
      t.subobject = subobject(out_.classes[l.cls], l.offset, l.cls);
      for (std::uint64_t a = t.address; t.entries.size() < kMaxVftableEntries; a += p) {
        if (meta_slots.contains(a)) break;  // the next table's locator
        auto value = v_.ptr(a);
        if (!value || *value == 0 || !v_.executable(*value)) break;
        t.entries.push_back(*value);
      }
      out_.vftables.push_back(std::move(t));
    }
    std::sort(out_.vftables.begin(), out_.vftables.end(),
              [](const Vftable &a, const Vftable &b) { return a.address < b.address; });
  }

  // The class whose subobject is at `offset` in `c`: `c` itself at 0, else
  // the first non-virtual base there (a preorder walk meets the most
  // derived such base first), else the only virtual base.
  std::size_t subobject(const ClassInfo &c, std::uint32_t offset, std::size_t self) const {
    if (offset == 0) return self;
    for (std::size_t i = 1; i < c.bases.size(); ++i) {
      const BaseClass &b = c.bases[i];
      if (!b.is_virtual() && b.mdisp >= 0 && static_cast<std::uint32_t>(b.mdisp) == offset)
        if (auto j = out_.index_of(b.type_descriptor)) return *j;
    }
    std::optional<std::size_t> only;
    std::set<std::uint64_t> virtuals;
    for (std::size_t i = 1; i < c.bases.size(); ++i)
      if (c.bases[i].is_virtual()) virtuals.insert(c.bases[i].type_descriptor);
    if (virtuals.size() == 1)
      if (auto j = out_.index_of(*virtuals.begin())) only = *j;
    return only.value_or(self);
  }

  View v_;
  Rtti out_;
  std::vector<const loader::Block *> blocks_;
  std::vector<std::vector<std::uint8_t>> bytes_;
};

}  // namespace

Rtti scan_rtti(const loader::Image &image) { return Scanner(image).run(); }

}  // namespace revkit::msvc
