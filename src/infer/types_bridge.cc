#include "revkit/infer/types_bridge.h"

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

types::TypeId to_type(const VType &t, types::TypeStore &store, const DataOrg &org) {
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
      return store.pointer_to(t.pointee.empty() ? store.void_type() : to_type(t.target(), store, org),
                              t.size ? t.size : org.pointer_size);
    case Meta::struct_: {
      types::AggregateType a;
      a.name = t.name;
      a.complete = false;
      return store.intern(types::Type(std::move(a)));
    }
    case Meta::code: {
      types::FunctionType f;
      f.ret = t.pointee.empty() ? store.void_type() : to_type(t.pointee[0], store, org);
      for (std::size_t i = 1; i < t.pointee.size(); ++i) f.params.push_back({{}, to_type(t.pointee[i], store, org)});
      f.varargs = t.name == "...";
      return store.function(std::move(f));
    }
    case Meta::unknown: break;
  }
  return store.undefined(t.size ? t.size : 1);
}

types::TypeId to_type(const Prototype &p, types::TypeStore &store, const DataOrg &org) {
  types::FunctionType f;
  f.ret = to_type(p.ret, store, org);
  for (const VType &t : p.params) f.params.push_back({{}, to_type(t, store, org)});
  f.varargs = p.varargs;
  return store.function(std::move(f));
}

}  // namespace revkit::infer
