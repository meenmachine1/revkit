#include "revkit/infer/types_bridge.h"

#include "revkit/infer/accesses.h"
#include "revkit/types/packing.h"

namespace revkit::infer {

namespace {

types::IntRank rank_of(const VType &t, const DataOrg &org) {
  switch (t.size) {
    case 1: return types::IntRank::Char;
    case 2: return types::IntRank::Short;
    case 4: return types::IntRank::Int;
    case 8: return org.long_size == 8 && !t.long_long ? types::IntRank::Long : types::IntRank::LongLong;
    case 16: return types::IntRank::Int128;
    default: return types::IntRank::Fixed;
  }
}

}  // namespace

types::TypeId to_type(const VType &t, types::TypeStore &store, const DataOrg &org, const StructureIds *structures) {
  switch (t.meta) {
    case Meta::void_: return store.void_type();
    case Meta::bool_: return store.bool_type(t.size ? t.size : 1);
    case Meta::char_: return store.int_type(1, org.char_signed, types::IntRank::PlainChar);
    case Meta::int_: return store.int_type(t.size, t.sign != Sign::is_unsigned, rank_of(t, org));
    case Meta::float_:
      switch (t.size) {
        case 4: return store.float_type(4, types::FloatKind::Float);
        case 8: return store.float_type(8, types::FloatKind::Double);
        default: return store.float_type(t.size, types::FloatKind::LongDouble);
      }
    case Meta::pointer:
      return store.pointer_to(t.pointee.empty() ? store.void_type() : to_type(t.target(), store, org, structures),
                              t.size ? t.size : org.pointer_size);
    case Meta::struct_: {
      if (structures != nullptr)
        if (auto it = structures->find(t.name); it != structures->end()) return it->second;
      types::AggregateType a;
      a.name = t.name;
      a.complete = false;
      return store.intern(types::Type(std::move(a)));
    }
    case Meta::code: {
      types::FunctionType f;
      f.ret = t.pointee.empty() ? store.void_type() : to_type(t.pointee[0], store, org, structures);
      for (std::size_t i = 1; i < t.pointee.size(); ++i) f.params.push_back({{}, to_type(t.pointee[i], store, org, structures)});
      f.varargs = t.name == "...";
      return store.function(std::move(f));
    }
    case Meta::unknown: break;
  }
  return store.undefined(t.size ? t.size : 1);
}

types::TypeId to_type(const Prototype &p, types::TypeStore &store, const DataOrg &org, const StructureIds *structures) {
  types::FunctionType f;
  f.ret = to_type(p.ret, store, org, structures);
  for (const VType &t : p.params) f.params.push_back({{}, to_type(t, store, org, structures)});
  f.varargs = p.varargs;
  return store.function(std::move(f));
}

StructureIds to_types(const std::vector<InferredStructure> &structures, types::TypeStore &store, const DataOrg &org) {
  StructureIds out;
  if (structures.empty()) return out;
  types::TypeGraph g;
  std::map<std::string, types::TypeId> local;
  for (const InferredStructure &s : structures) local.emplace(s.name, g.reserve());
  // A field's type: a pointer to an inferred structure points into the
  // graph, anything else is a store type.
  auto field_type = [&](const VType &t) -> types::TypeId {
    if (t.is_pointer() && t.target().meta == Meta::struct_)
      if (auto it = local.find(t.target().name); it != local.end())
        return g.add(types::Type(types::PointerType{it->second, t.size ? t.size : org.pointer_size}));
    if (t.meta == Meta::unknown || t.meta == Meta::struct_ || t.meta == Meta::code) return store.undefined(t.size ? t.size : 1);
    return to_type(t, store, org);
  };
  std::vector<std::pair<types::TypeId, std::uint32_t>> aggs;
  for (const InferredStructure &s : structures) {
    types::AggregateType a;
    a.kind = types::AggregateKind::Struct;
    a.name = s.name;
    a.size = s.size;
    a.complete = true;
    for (const InferredField &f : s.fields) {
      types::TypeId ft = f.type.meta == Meta::unknown ? store.undefined(f.size ? f.size : 1) : field_type(f.type);
      if (!ft.is_local() && store.size_of(ft) != f.size) ft = store.undefined(f.size ? f.size : 1);
      a.fields.push_back({field_name(f.offset), ft, f.offset * 8, 0});
    }
    const types::TypeId id = local.at(s.name);
    g.set(id, types::Type(std::move(a)));
    aggs.emplace_back(id, org.pointer_size);
  }
  types::infer_packing(g, store, aggs);
  const std::vector<types::TypeId> ids = store.intern(g);
  for (const auto &[name, id] : local) out.emplace(name, ids.at(id.index()));
  return out;
}

}  // namespace revkit::infer
