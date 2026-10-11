#include "define_type.h"

#include "type_record.h"

#include "revkit/types/print.h"

#include <stdexcept>

namespace revkit::backend {

using namespace revkit::types;

namespace {

std::string At(int i, const std::string &message) { return "assertions[" + std::to_string(i) + "]: " + message; }

constexpr std::pair<std::string_view, CallConv> kConventions[] = {
    {"", CallConv::Default},           {"__cdecl", CallConv::Cdecl},       {"__stdcall", CallConv::Stdcall},
    {"__fastcall", CallConv::Fastcall}, {"__thiscall", CallConv::Thiscall}, {"__vectorcall", CallConv::Vectorcall},
    {"__pascal", CallConv::Pascal},     {"__ms_abi", CallConv::Ms64},       {"__sysv_abi", CallConv::SysV},
    {"__regcall", CallConv::Regcall},
};

CallConv ConventionFrom(const std::string &name) {
  for (const auto &[n, cc] : kConventions)
    if (n == name) return cc;
  return CallConv::Other;
}

std::string ConventionName(CallConv cc) {
  for (const auto &[n, c] : kConventions)
    if (c == cc) return std::string(n);
  return "other";
}

IntRank RankFrom(pb::IntegerRank r) {
  switch (r) {
    case pb::INTEGER_RANK_CHAR: return IntRank::Char;
    case pb::INTEGER_RANK_SHORT: return IntRank::Short;
    case pb::INTEGER_RANK_INT: return IntRank::Int;
    case pb::INTEGER_RANK_LONG: return IntRank::Long;
    case pb::INTEGER_RANK_LONG_LONG: return IntRank::LongLong;
    case pb::INTEGER_RANK_INT128: return IntRank::Int128;
    case pb::INTEGER_RANK_WCHAR: return IntRank::WChar;
    case pb::INTEGER_RANK_CHAR8: return IntRank::Char8;
    case pb::INTEGER_RANK_CHAR16: return IntRank::Char16;
    case pb::INTEGER_RANK_CHAR32: return IntRank::Char32;
    default: return IntRank::Fixed;
  }
}

pb::IntegerRank RankTo(IntRank r) {
  switch (r) {
    case IntRank::Char: return pb::INTEGER_RANK_CHAR;
    case IntRank::Short: return pb::INTEGER_RANK_SHORT;
    case IntRank::Int: return pb::INTEGER_RANK_INT;
    case IntRank::Long: return pb::INTEGER_RANK_LONG;
    case IntRank::LongLong: return pb::INTEGER_RANK_LONG_LONG;
    case IntRank::Int128: return pb::INTEGER_RANK_INT128;
    case IntRank::WChar: return pb::INTEGER_RANK_WCHAR;
    case IntRank::Char8: return pb::INTEGER_RANK_CHAR8;
    case IntRank::Char16: return pb::INTEGER_RANK_CHAR16;
    case IntRank::Char32: return pb::INTEGER_RANK_CHAR32;
    default: return pb::INTEGER_RANK_UNSPECIFIED;
  }
}

FloatKind FloatFrom(pb::FloatKind k, std::uint64_t size) {
  switch (k) {
    case pb::FLOAT_KIND_HALF: return FloatKind::Half;
    case pb::FLOAT_KIND_FLOAT: return FloatKind::Float;
    case pb::FLOAT_KIND_DOUBLE: return FloatKind::Double;
    case pb::FLOAT_KIND_LONG_DOUBLE: return FloatKind::LongDouble;
    case pb::FLOAT_KIND_FLOAT128: return FloatKind::Float128;
    default: break;
  }
  return size == 2 ? FloatKind::Half : size == 4 ? FloatKind::Float : size == 8 ? FloatKind::Double : FloatKind::LongDouble;
}

pb::FloatKind FloatTo(FloatKind k) {
  switch (k) {
    case FloatKind::Half: return pb::FLOAT_KIND_HALF;
    case FloatKind::Float: return pb::FLOAT_KIND_FLOAT;
    case FloatKind::Double: return pb::FLOAT_KIND_DOUBLE;
    case FloatKind::LongDouble: return pb::FLOAT_KIND_LONG_DOUBLE;
    case FloatKind::Float128: return pb::FLOAT_KIND_FLOAT128;
  }
  return pb::FLOAT_KIND_UNSPECIFIED;
}

// Builds one batch: the store holds the stored types the batch references
// (interned from their records), the graph one node per define_type.
class Builder {
 public:
  Builder(const google::protobuf::RepeatedPtrField<pb::AssertionInput> &in, std::uint32_t pointer_size,
          const ClosureFn &closure)
      : in_(in), pointer_size_(pointer_size), closure_(closure), local_(static_cast<std::size_t>(in.size())) {}

  std::string Run(DefinedTypes &out) {
    const auto n = static_cast<std::size_t>(in_.size());
    out.hash.assign(n, {});
    out.record.assign(n, {});
    out.stored.assign(n, {});
    for (int i = 0; i < in_.size(); ++i)
      if (in_[i].body().has_define_type()) local_[static_cast<std::size_t>(i)] = graph_.reserve();
    for (int i = 0; i < in_.size(); ++i) {
      if (!in_[i].body().has_define_type()) continue;
      Type t;
      if (auto e = Convert(in_[i].body().define_type().type(), t); !e.empty()) return At(i, e);
      graph_.set(local_[static_cast<std::size_t>(i)], std::move(t));
    }
    std::vector<TypeId> ids;
    try {
      ids = store_.intern(graph_);
    } catch (const std::invalid_argument &e) {
      for (int i = 0; i < in_.size(); ++i)
        if (in_[i].body().has_define_type()) return At(i, std::string("define_type: ") + e.what());
    }
    for (int i = 0; i < in_.size(); ++i) {
      if (!in_[i].body().has_define_type()) continue;
      const auto u = static_cast<std::size_t>(i);
      const TypeId id = ids[local_[u].index()];
      out.hash[u] = store_.hash(id).hex();
      out.record[u] = EncodeTypeRecord(store_, id);
    }
    for (int i = 0; i < in_.size(); ++i) {
      if (!in_[i].body().has_define_type()) continue;
      pb::AssertionBody body = in_[i].body();
      pb::TypeNode &node = *body.mutable_define_type()->mutable_type();
      auto fix = [&](pb::TypeNodeRef *ref) {
        if (ref->kind_case() == pb::TypeNodeRef::kAssertionIndex) ref->set_hash(out.hash[ref->assertion_index()]);
      };
      if (node.has_target()) fix(node.mutable_target());
      for (auto &f : *node.mutable_fields()) fix(f.mutable_type());
      for (auto &p : *node.mutable_params()) fix(p.mutable_type());
      out.stored[static_cast<std::size_t>(i)] = std::move(body);
    }
    return {};
  }

 private:
  // A reference as a store id (stored types) or graph id (this batch).
  std::string Resolve(const pb::TypeNodeRef &ref, TypeId &out) {
    switch (ref.kind_case()) {
      case pb::TypeNodeRef::kHash: {
        if (auto it = by_hash_.find(ref.hash()); it != by_hash_.end()) {
          out = it->second;
          return {};
        }
        auto records = closure_(ref.hash());
        if (records.empty()) return "unknown type hash " + ref.hash() + " (not defined in this program)";
        auto ids = InternRecords(std::map<std::string, std::string>(records.begin(), records.end()), store_);
        by_hash_.insert(ids.begin(), ids.end());
        out = by_hash_.at(ref.hash());
        return {};
      }
      case pb::TypeNodeRef::kAssertionIndex: {
        const std::uint32_t j = ref.assertion_index();
        if (j >= local_.size() || !in_[static_cast<int>(j)].body().has_define_type())
          return "assertion_index " + std::to_string(j) + " is not a define_type of this request";
        out = local_[j];
        return {};
      }
      case pb::TypeNodeRef::KIND_NOT_SET: break;
    }
    return "type reference is empty";
  }

  std::string Required(const pb::TypeNode &node, TypeId &out, const char *what) {
    if (!node.has_target()) return std::string(what) + " is required";
    return Resolve(node.target(), out);
  }

  std::string Convert(const pb::TypeNode &node, Type &t) {
    const std::uint64_t size = node.size();
    if (size > (std::uint64_t{1} << 32)) return "size is too large";
    const auto size32 = static_cast<std::uint32_t>(size);
    switch (node.kind()) {
      case pb::TYPE_KIND_VOID: t = VoidType{}; return {};
      case pb::TYPE_KIND_BOOL: t = BoolType{size32 ? size32 : 1}; return {};
      case pb::TYPE_KIND_UNDEFINED: t = UndefinedType{size32 ? size32 : 1}; return {};
      case pb::TYPE_KIND_INT:
      case pb::TYPE_KIND_UINT:
        if (size == 0 || size > 16) return "integer size must be 1 to 16";
        t = IntType{size32, node.kind() == pb::TYPE_KIND_INT, RankFrom(node.rank())};
        return {};
      case pb::TYPE_KIND_CHAR: t = IntType{size32 ? size32 : 1, node.is_signed(), IntRank::PlainChar}; return {};
      case pb::TYPE_KIND_FLOAT:
        if (size == 0 || size > 32) return "float size must be 1 to 32";
        t = FloatType{size32, FloatFrom(node.float_kind(), node.is_complex() ? size / 2 : size), node.is_complex()};
        return {};
      case pb::TYPE_KIND_POINTER: {
        PointerType p;
        if (auto e = Required(node, p.target, "pointer target"); !e.empty()) return e;
        p.size = size32 ? size32 : pointer_size_;
        p.kind = node.reference() == pb::TYPE_NODE_REFERENCE_LVALUE   ? PointerKind::LValueRef
                 : node.reference() == pb::TYPE_NODE_REFERENCE_RVALUE ? PointerKind::RValueRef
                                                                       : PointerKind::Pointer;
        t = p;
        return {};
      }
      case pb::TYPE_KIND_ARRAY: {
        ArrayType a;
        if (auto e = Required(node, a.element, "array element (target)"); !e.empty()) return e;
        a.count = node.count();
        t = a;
        return {};
      }
      case pb::TYPE_KIND_STRUCT:
      case pb::TYPE_KIND_UNION: {
        AggregateType a;
        a.kind = node.kind() == pb::TYPE_KIND_UNION ? AggregateKind::Union
                 : node.is_class()                  ? AggregateKind::Class
                                                    : AggregateKind::Struct;
        a.name = node.name();
        a.size = size;
        a.alignment = node.alignment();
        a.packed = node.packed();
        a.complete = !node.incomplete();
        for (int k = 0; k < node.fields_size(); ++k) {
          const auto &f = node.fields(k);
          Field field;
          field.name = f.name();
          if (!f.has_type()) return "fields[" + std::to_string(k) + "].type is required";
          if (auto e = Resolve(f.type(), field.type); !e.empty()) return "fields[" + std::to_string(k) + "]: " + e;
          if (f.offset() > size) return "fields[" + std::to_string(k) + "] starts beyond the aggregate's size";
          field.bit_offset = f.offset() * 8 + f.bit_offset();
          field.bit_size = f.bit_size();
          a.fields.push_back(std::move(field));
        }
        t = std::move(a);
        return {};
      }
      case pb::TYPE_KIND_ENUM: {
        EnumType e;
        e.name = node.name();
        e.size = size32 ? size32 : 4;
        e.is_signed = node.is_signed();
        e.complete = !node.incomplete();
        for (const auto &v : node.enumerators()) e.values.push_back(Enumerator{v.name(), v.value()});
        t = std::move(e);
        return {};
      }
      case pb::TYPE_KIND_TYPEDEF: {
        if (node.name().empty()) return "a typedef needs a name";
        TypedefType d;
        d.name = node.name();
        if (auto e = Required(node, d.target, "typedef target"); !e.empty()) return e;
        t = std::move(d);
        return {};
      }
      case pb::TYPE_KIND_QUALIFIED: {
        QualifiedType q;
        if (auto e = Required(node, q.target, "qualified target"); !e.empty()) return e;
        const auto &b = node.qualifiers();
        q.quals = static_cast<std::uint8_t>((b.is_const() ? kConst : 0) | (b.is_volatile() ? kVolatile : 0) |
                                            (b.is_restrict() ? kRestrict : 0) | (b.is_atomic() ? kAtomic : 0));
        t = q;
        return {};
      }
      case pb::TYPE_KIND_FUNCTION: {
        FunctionType f;
        if (node.has_target()) {
          if (auto e = Resolve(node.target(), f.ret); !e.empty()) return "return type: " + e;
        } else {
          f.ret = store_.void_type();
        }
        for (int k = 0; k < node.params_size(); ++k) {
          const auto &p = node.params(k);
          Param param;
          param.name = p.name();
          if (!p.has_type()) return "params[" + std::to_string(k) + "].type is required";
          if (auto e = Resolve(p.type(), param.type); !e.empty()) return "params[" + std::to_string(k) + "]: " + e;
          f.params.push_back(std::move(param));
        }
        f.varargs = node.varargs();
        f.cc = ConventionFrom(node.calling_convention());
        t = std::move(f);
        return {};
      }
      default: break;
    }
    return "type.kind is required";
  }

  const google::protobuf::RepeatedPtrField<pb::AssertionInput> &in_;
  std::uint32_t pointer_size_;
  const ClosureFn &closure_;
  TypeStore store_;
  TypeGraph graph_;
  std::vector<TypeId> local_;
  std::map<std::string, TypeId> by_hash_;
};

}  // namespace

std::string CallingConventionName(CallConv cc) { return ConventionName(cc); }

pb::TypeNode TypeNodeOf(const TypeStore &store, TypeId id, const std::function<pb::TypeNodeRef(TypeId)> &ref) {
  pb::TypeNode n;
  const Type &ty = store.get(id);
  std::visit(
      [&](const auto &d) {
        using D = std::decay_t<decltype(d)>;
        if constexpr (std::is_same_v<D, VoidType>) {
          n.set_kind(pb::TYPE_KIND_VOID);
        } else if constexpr (std::is_same_v<D, BoolType>) {
          n.set_kind(pb::TYPE_KIND_BOOL);
          n.set_size(d.size);
        } else if constexpr (std::is_same_v<D, IntType>) {
          if (d.rank == IntRank::PlainChar) {
            n.set_kind(pb::TYPE_KIND_CHAR);
            n.set_is_signed(d.is_signed);
          } else {
            n.set_kind(d.is_signed ? pb::TYPE_KIND_INT : pb::TYPE_KIND_UINT);
            n.set_rank(RankTo(d.rank));
          }
          n.set_size(d.size);
        } else if constexpr (std::is_same_v<D, FloatType>) {
          n.set_kind(pb::TYPE_KIND_FLOAT);
          n.set_size(d.size);
          n.set_float_kind(FloatTo(d.kind));
          n.set_is_complex(d.complex);
        } else if constexpr (std::is_same_v<D, PointerType>) {
          n.set_kind(pb::TYPE_KIND_POINTER);
          n.set_size(d.size);
          *n.mutable_target() = ref(d.target);
          n.set_reference(d.kind == PointerKind::LValueRef   ? pb::TYPE_NODE_REFERENCE_LVALUE
                          : d.kind == PointerKind::RValueRef ? pb::TYPE_NODE_REFERENCE_RVALUE
                                                             : pb::TYPE_NODE_REFERENCE_UNSPECIFIED);
        } else if constexpr (std::is_same_v<D, ArrayType>) {
          n.set_kind(pb::TYPE_KIND_ARRAY);
          *n.mutable_target() = ref(d.element);
          n.set_count(d.count);
        } else if constexpr (std::is_same_v<D, AggregateType>) {
          n.set_kind(d.kind == AggregateKind::Union ? pb::TYPE_KIND_UNION : pb::TYPE_KIND_STRUCT);
          n.set_is_class(d.kind == AggregateKind::Class);
          n.set_name(d.name);
          n.set_size(d.size);
          n.set_alignment(d.alignment);
          n.set_packed(d.packed);
          n.set_incomplete(!d.complete);
          for (const Field &f : d.fields) {
            auto *out = n.add_fields();
            out->set_name(f.name);
            *out->mutable_type() = ref(f.type);
            out->set_offset(f.bit_offset / 8);
            out->set_bit_offset(static_cast<std::uint32_t>(f.bit_offset % 8));
            out->set_bit_size(f.bit_size);
          }
        } else if constexpr (std::is_same_v<D, EnumType>) {
          n.set_kind(pb::TYPE_KIND_ENUM);
          n.set_name(d.name);
          n.set_size(d.size);
          n.set_is_signed(d.is_signed);
          n.set_incomplete(!d.complete);
          for (const Enumerator &v : d.values) {
            auto *out = n.add_enumerators();
            out->set_name(v.name);
            out->set_value(v.value);
          }
        } else if constexpr (std::is_same_v<D, TypedefType>) {
          n.set_kind(pb::TYPE_KIND_TYPEDEF);
          n.set_name(d.name);
          *n.mutable_target() = ref(d.target);
        } else if constexpr (std::is_same_v<D, QualifiedType>) {
          n.set_kind(pb::TYPE_KIND_QUALIFIED);
          *n.mutable_target() = ref(d.target);
          auto *q = n.mutable_qualifiers();
          q->set_is_const(d.quals & kConst);
          q->set_is_volatile(d.quals & kVolatile);
          q->set_is_restrict(d.quals & kRestrict);
          q->set_is_atomic(d.quals & kAtomic);
        } else if constexpr (std::is_same_v<D, FunctionType>) {
          n.set_kind(pb::TYPE_KIND_FUNCTION);
          if (store.kind(d.ret) != Kind::Void) *n.mutable_target() = ref(d.ret);
          for (const Param &p : d.params) {
            auto *out = n.add_params();
            out->set_name(p.name);
            *out->mutable_type() = ref(p.type);
          }
          n.set_varargs(d.varargs);
          n.set_calling_convention(ConventionName(d.cc));
        } else if constexpr (std::is_same_v<D, UndefinedType>) {
          n.set_kind(pb::TYPE_KIND_UNDEFINED);
          n.set_size(d.size);
        }
      },
      ty.data);
  return n;
}

std::string DefineTypes(const google::protobuf::RepeatedPtrField<pb::AssertionInput> &assertions,
                        std::uint32_t pointer_size, const ClosureFn &closure, DefinedTypes &out) {
  return Builder(assertions, pointer_size, closure).Run(out);
}

void DescribeType(const TypeStore &store, TypeId id, pb::TypeDefinition &t) {
  const Type &ty = store.get(id);
  auto h = [&](TypeId ref) { return store.hash(ref).hex(); };
  t.set_size(store.size_of(id));
  t.set_alignment(store.align_of(id));
  t.set_display(type_name(store, id));
  t.set_c_definition(definition(store, id));
  std::visit(
      [&](const auto &d) {
        using D = std::decay_t<decltype(d)>;
        if constexpr (std::is_same_v<D, VoidType>) {
          t.set_kind(pb::TYPE_KIND_VOID);
        } else if constexpr (std::is_same_v<D, BoolType>) {
          t.set_kind(pb::TYPE_KIND_BOOL);
        } else if constexpr (std::is_same_v<D, IntType>) {
          t.set_kind(d.rank == IntRank::PlainChar ? pb::TYPE_KIND_CHAR
                     : d.is_signed               ? pb::TYPE_KIND_INT
                                                 : pb::TYPE_KIND_UINT);
          t.set_rank(RankTo(d.rank));
        } else if constexpr (std::is_same_v<D, FloatType>) {
          t.set_kind(pb::TYPE_KIND_FLOAT);
          t.set_float_kind(FloatTo(d.kind));
          t.set_is_complex(d.complex);
        } else if constexpr (std::is_same_v<D, PointerType>) {
          t.set_kind(pb::TYPE_KIND_POINTER);
          t.mutable_pointer()->set_target_hash(h(d.target));
          t.set_reference(d.kind == PointerKind::LValueRef   ? pb::TYPE_NODE_REFERENCE_LVALUE
                          : d.kind == PointerKind::RValueRef ? pb::TYPE_NODE_REFERENCE_RVALUE
                                                             : pb::TYPE_NODE_REFERENCE_UNSPECIFIED);
        } else if constexpr (std::is_same_v<D, ArrayType>) {
          t.set_kind(pb::TYPE_KIND_ARRAY);
          t.mutable_array()->set_element_hash(h(d.element));
          t.mutable_array()->set_count(d.count);
        } else if constexpr (std::is_same_v<D, AggregateType>) {
          t.set_kind(d.kind == AggregateKind::Union ? pb::TYPE_KIND_UNION : pb::TYPE_KIND_STRUCT);
          t.set_is_class(d.kind == AggregateKind::Class);
          t.set_name(d.name);
          t.set_complete(d.complete);
          auto *c = t.mutable_composite();
          c->set_packed(d.packed);
          for (const Field &f : d.fields) {
            auto *out = c->add_fields();
            out->set_name(f.name);
            out->set_offset(f.bit_offset / 8);
            out->set_type_hash(h(f.type));
            if (f.bit_size != 0) {
              out->set_bit_offset(static_cast<std::uint32_t>(f.bit_offset % 8));
              out->set_bit_size(f.bit_size);
            }
          }
        } else if constexpr (std::is_same_v<D, EnumType>) {
          t.set_kind(pb::TYPE_KIND_ENUM);
          t.set_name(d.name);
          t.set_complete(d.complete);
          auto *e = t.mutable_enumeration();
          for (const Enumerator &v : d.values) {
            auto *out = e->add_values();
            out->set_name(v.name);
            out->set_value(v.value);
          }
        } else if constexpr (std::is_same_v<D, TypedefType>) {
          t.set_kind(pb::TYPE_KIND_TYPEDEF);
          t.set_name(d.name);
          t.mutable_typedef_type()->set_target_hash(h(d.target));
        } else if constexpr (std::is_same_v<D, QualifiedType>) {
          t.set_kind(pb::TYPE_KIND_QUALIFIED);
          auto *q = t.mutable_qualified();
          q->set_target_hash(h(d.target));
          q->set_is_const(d.quals & kConst);
          q->set_is_volatile(d.quals & kVolatile);
          q->set_is_restrict(d.quals & kRestrict);
          q->set_is_atomic(d.quals & kAtomic);
        } else if constexpr (std::is_same_v<D, FunctionType>) {
          t.set_kind(pb::TYPE_KIND_FUNCTION);
          auto *f = t.mutable_function();
          f->set_return_hash(h(d.ret));
          for (const Param &p : d.params) {
            auto *out = f->add_params();
            out->set_name(p.name);
            out->set_type_hash(h(p.type));
          }
          f->set_varargs(d.varargs);
          f->set_calling_convention(ConventionName(d.cc));
        } else if constexpr (std::is_same_v<D, UndefinedType>) {
          t.set_kind(pb::TYPE_KIND_UNDEFINED);
        }
      },
      ty.data);
}

}  // namespace revkit::backend
