// RTTI as markup: the structures typed and named as Ghidra's RTTI analyzer
// names them, vftables typed as structs of function pointers, functions at
// their entries, and the class structs `this` points to.

#include "markup_internal.h"

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <map>
#include <set>

namespace revkit::msvc::detail {

namespace {

// A C identifier from a function's name: its last component, other
// characters as '_'.
std::string field_name(const std::string &qualified) {
  std::string base = qualified;
  // The last "::" outside template arguments.
  int depth = 0;
  std::size_t cut = std::string::npos;
  for (std::size_t i = 0; i + 1 < base.size(); ++i) {
    if (base[i] == '<') ++depth;
    else if (base[i] == '>') --depth;
    else if (depth == 0 && base[i] == ':' && base[i + 1] == ':') cut = i + 2;
  }
  if (cut != std::string::npos) base = base.substr(cut);
  std::string out;
  for (char c : base) out += (std::isalnum(static_cast<unsigned char>(c)) || c == '_') ? c : '_';
  if (out.empty() || std::isdigit(static_cast<unsigned char>(out[0]))) out = "_" + out;
  return out;
}

struct Appearance {
  std::size_t table = 0;  // index into rtti.vftables
  std::size_t slot = 0;
};

}  // namespace

void rtti_markup(Builder &b, const Rtti &rtti, const MarkupOptions &options) {
  if (rtti.classes.empty()) return;
  types::TypeStore &st = b.store();
  const unsigned p = b.ptr();
  const bool wide = b.v.wide();

  // ---- the structures' types (Ghidra's names) ----
  const types::TypeId pmd = b.struct_("PMD", {{"mdisp", b.i32()}, {"pdisp", b.i32()}, {"vdisp", b.i32()}});
  const types::TypeId td = b.struct_("TypeDescriptor", {{"pVFTable", b.voidp()}, {"spare", b.voidp()}});
  // The ones that point at each other on 32-bit images, built forward.
  types::AggregateType chd_fwd{types::AggregateKind::Struct, "RTTIClassHierarchyDescriptor", 0, 0, false, false, {}};
  const types::TypeId chd_decl = st.intern(types::Type(chd_fwd));
  const types::TypeId bcd = b.struct_("RTTIBaseClassDescriptor", {{"pTypeDescriptor", b.ref(td)},
                                                                    {"numContainedBases", b.dword()},
                                                                    {"where", pmd},
                                                                    {"attributes", b.dword()},
                                                                    {"pClassDescriptor", b.ref(chd_decl)}});
  const types::TypeId bca_elem = b.ref(bcd);
  const types::TypeId chd = b.struct_("RTTIClassHierarchyDescriptor", {{"signature", b.dword()},
                                                                         {"attributes", b.dword()},
                                                                         {"numBaseClasses", b.dword()},
                                                                         {"pBaseClassArray", b.ref(bca_elem)}});
  std::vector<Builder::F> col_fields{{"signature", b.dword()},
                                     {"offset", b.dword()},
                                     {"cdOffset", b.dword()},
                                     {"pTypeDescriptor", b.ref(td)},
                                     {"pClassDescriptor", b.ref(chd)}};
  if (wide) col_fields.push_back({"pSelf", b.ibo32()});
  const types::TypeId col = b.struct_("RTTICompleteObjectLocator", col_fields);

  // ---- type descriptors ----
  std::map<std::uint64_t, std::size_t> vft_targets;  // TypeDescriptor.pVFTable values
  for (const ClassInfo &c : rtti.classes) {
    b.data(c.type_descriptor, td, c.name + "::RTTI_Type_Descriptor");
    // The name: a string after the two pointers.
    const std::uint64_t at = c.type_descriptor + 2 * p;
    b.string(at, c.name_length);
    if (auto vft = b.v.ptr(c.type_descriptor); vft && *vft != 0) ++vft_targets[*vft];
  }
  // Every TypeDescriptor points at type_info's vftable.
  if (vft_targets.size() == 1 && options.named && options.named(vft_targets.begin()->first).empty())
    b.label(vft_targets.begin()->first, "type_info::vftable");
  b.out.counts["rtti_classes"] = rtti.classes.size();

  // ---- hierarchies, base class arrays and descriptors ----
  std::set<std::uint64_t> done;
  for (const ClassInfo &c : rtti.classes) {
    if (c.hierarchy == 0 || c.bases.empty() || !done.insert(c.hierarchy).second) continue;
    b.data(c.hierarchy, chd, c.name + "::RTTI_Class_Hierarchy_Descriptor");
    if (c.base_array != 0)
      b.data(c.base_array, bca_elem, c.name + "::RTTI_Base_Class_Array", c.bases.size(), true);
    for (const BaseClass &bc : c.bases) {
      if (!done.insert(bc.descriptor).second) continue;
      const std::string owner = bc.name.empty() ? c.name : bc.name;
      b.data(bc.descriptor, bcd,
             owner + "::RTTI_Base_Class_Descriptor_at_(" + std::to_string(bc.mdisp) + "," + std::to_string(bc.pdisp) +
                 "," + std::to_string(bc.vdisp) + "," + std::to_string(bc.attributes) + ")");
    }
  }

  // ---- locators ----
  std::map<std::size_t, std::size_t> tables_of;  // per class
  for (const Vftable &t : rtti.vftables) ++tables_of[t.cls];
  auto for_suffix = [&](const Vftable &t) -> std::string {
    if (t.offset == 0 || tables_of[t.cls] == 1) return "";
    if (t.subobject != t.cls) {
      const std::string &n = rtti.classes[t.subobject].name;
      return "_for_" + field_name(n);
    }
    char buf[32];
    std::snprintf(buf, sizeof buf, "_at_%x", t.offset);
    return buf;
  };
  std::map<std::uint64_t, const Vftable *> table_of_locator;
  for (const Vftable &t : rtti.vftables) table_of_locator.emplace(t.locator, &t);
  for (const Locator &l : rtti.locators) {
    std::string suffix;
    if (auto it = table_of_locator.find(l.address); it != table_of_locator.end()) suffix = for_suffix(*it->second);
    b.data(l.address, col, rtti.classes[l.cls].name + "::RTTI_Complete_Object_Locator" + suffix);
  }

  // ---- functions in vftables, and who owns each ----
  std::map<std::uint64_t, std::vector<Appearance>> seen;
  for (std::size_t t = 0; t < rtti.vftables.size(); ++t)
    for (std::size_t i = 0; i < rtti.vftables[t].entries.size(); ++i)
      seen[rtti.vftables[t].entries[i]].push_back({t, i});
  // A class and its bases (all, or those at offset 0: the same `this`).
  auto bases_of = [&](std::size_t ci, bool zero_offset) {
    std::set<std::size_t> out{ci};
    for (std::size_t k = 1; k < rtti.classes[ci].bases.size(); ++k) {
      const BaseClass &bc = rtti.classes[ci].bases[k];
      if (zero_offset && (bc.is_virtual() || bc.mdisp != 0)) continue;
      if (auto j = rtti.index_of(bc.type_descriptor)) out.insert(*j);
    }
    return out;
  };
  // The most derived class every one of `classes` is or derives from.
  auto common_base = [&](const std::vector<std::size_t> &classes, bool zero_offset) -> std::optional<std::size_t> {
    if (classes.empty()) return std::nullopt;
    std::set<std::size_t> common = bases_of(classes[0], zero_offset);
    for (std::size_t k = 1; k < classes.size() && !common.empty(); ++k) {
      std::set<std::size_t> b = bases_of(classes[k], zero_offset), keep;
      std::set_intersection(common.begin(), common.end(), b.begin(), b.end(), std::inserter(keep, keep.begin()));
      common = std::move(keep);
    }
    std::optional<std::size_t> best;
    for (std::size_t c : common)
      if (!best || rtti.classes[c].bases.size() > rtti.classes[*best].bases.size()) best = c;
    return best;
  };
  struct Owner {
    std::optional<std::size_t> owner;  // the class it is named after
    std::optional<std::size_t> slot;
    std::string table;  // the table the slot is in, when it is a base's: "Named_"
    std::optional<std::size_t> self;   // the class `this` points to
  };
  std::map<std::uint64_t, Owner> owners;
  for (const auto &[entry, apps] : seen) {
    std::vector<std::size_t> tables, subs;
    for (const Appearance &a : apps) {
      tables.push_back(rtti.vftables[a.table].cls);
      subs.push_back(rtti.vftables[a.table].subobject);
    }
    Owner o;
    o.owner = common_base(tables, false);
    o.self = common_base(subs, true);
    if (o.owner) {
      for (const Appearance &a : apps)
        if (!o.slot && rtti.vftables[a.table].cls == *o.owner) {
          o.slot = a.slot;
          const Vftable &t = rtti.vftables[a.table];
          if (t.subobject != t.cls) o.table = field_name(rtti.classes[t.subobject].name) + "_";
        }
      if (!o.slot && std::all_of(apps.begin(), apps.end(), [&](const Appearance &a) { return a.slot == apps[0].slot; }))
        o.slot = apps[0].slot;
    }
    owners.emplace(entry, o);
  }

  // ---- class structs: the classes `this` and vftables need ----
  // Each class's primary vftable (offset 0), if any.
  std::map<std::size_t, const Vftable *> primary;
  for (const Vftable &t : rtti.vftables)
    if (t.offset == 0) primary.emplace(t.cls, &t);
  std::set<std::size_t> wanted;
  for (const Vftable &t : rtti.vftables) wanted.insert(t.subobject);
  for (const auto &[entry, o] : owners)
    if (o.self) wanted.insert(*o.self);
  // How far each class's methods reach through `this`, and so its size:
  // at least a pointer (the vftable pointer), its own methods' accesses,
  // and each non-virtual base's struct at its offset.
  std::map<std::size_t, std::uint64_t> reach;
  if (options.this_extent)
    for (const auto &[entry, o] : owners)
      if (o.self) reach[*o.self] = std::max(reach[*o.self], options.this_extent(entry));
  std::vector<std::size_t> order(wanted.begin(), wanted.end());
  std::sort(order.begin(), order.end(),
            [&](std::size_t x, std::size_t y) { return rtti.classes[x].bases.size() < rtti.classes[y].bases.size(); });
  std::map<std::size_t, std::uint64_t> size_of;
  for (std::size_t ci : order) {
    std::uint64_t n = std::max<std::uint64_t>(p, reach[ci]);
    for (std::size_t k = 1; k < rtti.classes[ci].bases.size(); ++k) {
      const BaseClass &bc = rtti.classes[ci].bases[k];
      if (bc.is_virtual() || bc.mdisp < 0) continue;
      if (auto j = rtti.index_of(bc.type_descriptor); j && size_of.contains(*j))
        n = std::max<std::uint64_t>(n, static_cast<std::uint64_t>(bc.mdisp) + size_of[*j]);
    }
    n = std::min<std::uint64_t>((n + p - 1) / p * p, 1u << 20);
    size_of[ci] = n;
  }
  // Names for vftable fields: what the entry is already called, else vfuncN.
  auto entry_field = [&](std::uint64_t entry, std::size_t slot, std::set<std::string> &used) {
    std::string n;
    if (options.named) n = options.named(entry);
    n = n.empty() ? "vfunc" + std::to_string(slot) : field_name(n);
    std::string unique = n;
    for (int k = 2; !used.insert(unique).second; ++k) unique = n + "_" + std::to_string(k);
    return unique;
  };
  // A class's vftable layout: its own primary table, else the slots every
  // table of a subobject at offset 0 of it shares (a base without a table
  // of its own, as an abstract class's is optimized away).
  auto layout_of = [&](std::size_t ci) -> std::vector<std::optional<std::uint64_t>> {
    if (auto it = primary.find(ci); it != primary.end())
      return {it->second->entries.begin(), it->second->entries.end()};
    std::vector<const Vftable *> tables;
    for (const Vftable &t : rtti.vftables)
      if (bases_of(t.subobject, true).contains(ci)) tables.push_back(&t);
    if (tables.empty()) return {};
    std::size_t n = SIZE_MAX;
    for (const Vftable *t : tables) n = std::min(n, t->entries.size());
    std::vector<std::optional<std::uint64_t>> out(n);
    for (std::size_t i = 0; i < n; ++i) {
      out[i] = tables[0]->entries[i];
      for (const Vftable *t : tables)
        if (t->entries[i] != *out[i]) out[i].reset();
    }
    return out;
  };
  const types::TypeId ret = st.undefined(p);
  const types::CallConv cc = wide ? types::CallConv::Default : types::CallConv::Thiscall;
  std::map<std::size_t, types::TypeId> class_ptr, method;  // per class: `C *`, `undefined C::f(C *this, ...)`
  for (std::size_t ci : wanted) {
    const ClassInfo &c = rtti.classes[ci];
    const auto kind = c.is_struct ? types::AggregateKind::Struct : types::AggregateKind::Class;
    types::TypeId given;
    if (options.class_type) given = options.class_type(c.name, st);
    types::TypeGraph g;
    const types::TypeId cls = given.valid() ? given : g.reserve();
    const types::TypeId cls_ptr = g.add(types::PointerType{cls, p});
    types::FunctionType fn;
    fn.ret = ret;
    fn.params.push_back({"this", cls_ptr});
    fn.varargs = true;
    fn.cc = cc;
    const types::TypeId fn_id = g.add(fn);
    const types::TypeId fn_ptr = g.add(types::PointerType{fn_id, p});
    types::TypeId vft_struct;
    if (const auto slots = layout_of(ci); !slots.empty()) {
      types::AggregateType v;
      v.kind = types::AggregateKind::Struct;
      v.name = c.name + "_vftable";
      v.size = std::uint64_t{p} * slots.size();
      std::set<std::string> used;
      for (std::size_t i = 0; i < slots.size(); ++i) {
        std::string name = slots[i] ? entry_field(*slots[i], i, used) : "vfunc" + std::to_string(i);
        if (!slots[i]) used.insert(name);
        v.fields.push_back({name, fn_ptr, std::uint64_t{i} * p * 8, 0});
      }
      vft_struct = g.add(types::Type(std::move(v)));
    }
    if (!given.valid()) {
      types::AggregateType a;
      a.kind = kind;
      a.name = c.name;
      a.size = size_of.contains(ci) ? size_of[ci] : p;
      const types::TypeId vptr = vft_struct.valid() ? g.add(types::PointerType{vft_struct, p})
                                                    : g.add(types::PointerType{st.pointer_to(st.void_type(), p), p});
      a.fields.push_back({"vftable", vptr, 0, 0});
      g.set(cls, types::Type(std::move(a)));
    }
    std::vector<types::TypeId> ids;
    try {
      ids = st.intern(g);
    } catch (const std::exception &e) {
      b.out.warnings.push_back("RTTI: class " + c.name + ": " + e.what());
      continue;
    }
    auto id = [&](types::TypeId local) { return local.is_local() ? ids[local.index()] : local; };
    class_ptr[ci] = id(cls_ptr);
    method[ci] = id(fn_id);
    b.out.classes.push_back({c.name, id(cls), vft_struct.valid() ? id(vft_struct) : types::TypeId()});
  }
  std::sort(b.out.classes.begin(), b.out.classes.end(),
            [](const ClassStruct &x, const ClassStruct &y) { return x.name < y.name; });

  // ---- vftables: the locator slot before each, the table as a struct ----
  for (const Vftable &t : rtti.vftables) {
    const ClassInfo &c = rtti.classes[t.cls];
    const std::string suffix = for_suffix(t);
    b.data(t.meta, b.pointer(col), c.name + "::vftable_meta_ptr" + suffix);
    if (t.entries.empty()) {
      b.label(t.address, c.name + "::vftable" + suffix);
      continue;
    }
    types::TypeId type;
    if (t.offset == 0 && t.subobject == t.cls) {
      for (const ClassStruct &k : b.out.classes)
        if (k.name == c.name && k.vftable.valid() && st.size_of(k.vftable) == t.entries.size() * p) type = k.vftable;
    }
    if (!type.valid()) {
      // A table of another subobject: its own struct, whose functions take
      // that subobject's class.
      auto m = method.find(t.subobject);
      const types::TypeId fp = m != method.end() ? b.pointer(m->second) : b.voidp();
      std::vector<Builder::F> fields;
      std::set<std::string> used;
      for (std::size_t i = 0; i < t.entries.size(); ++i) fields.push_back({entry_field(t.entries[i], i, used), fp});
      type = b.struct_(c.name + "_vftable" + suffix, fields);
    }
    b.data(t.address, type, c.name + "::vftable" + suffix);
  }
  b.out.counts["vftables"] = rtti.vftables.size();

  // ---- the functions ----
  std::size_t typed = 0;
  for (const auto &[entry, o] : owners) {
    FunctionDef f;
    f.entry = entry;
    f.why = "vftable";
    const bool has_name = options.named && !options.named(entry).empty();
    if (o.owner && o.slot && !has_name) f.name = rtti.classes[*o.owner].name + "::" + o.table + "vfunc" + std::to_string(*o.slot);
    if (o.self && method.contains(*o.self)) {
      f.this_type = class_ptr[*o.self];
      f.prototype = method[*o.self];
      ++typed;
    }
    b.function(std::move(f));
  }
  b.out.counts["virtual_functions"] = seen.size();
  b.out.counts["typed_this"] = typed;
}

}  // namespace revkit::msvc::detail
