#include "type_record.h"

#include "revkit/facts/codec.h"

namespace revkit::backend {

using facts::Decoder;
using facts::DecodeError;
using facts::Encoder;
using namespace revkit::types;

namespace {

void EncodeData(Encoder &e, const Type &t) {
  e.u8(static_cast<std::uint8_t>(t.kind()));
  std::visit(
      [&](const auto &d) {
        using D = std::decay_t<decltype(d)>;
        if constexpr (std::is_same_v<D, BoolType> || std::is_same_v<D, UndefinedType>) {
          e.varint(d.size);
        } else if constexpr (std::is_same_v<D, IntType>) {
          e.varint(d.size);
          facts::encode(e, d.is_signed);
          e.u8(static_cast<std::uint8_t>(d.rank));
        } else if constexpr (std::is_same_v<D, FloatType>) {
          e.varint(d.size);
          e.u8(static_cast<std::uint8_t>(d.kind));
          facts::encode(e, d.complex);
        } else if constexpr (std::is_same_v<D, PointerType>) {
          e.varint(d.size);
          e.u8(static_cast<std::uint8_t>(d.kind));
        } else if constexpr (std::is_same_v<D, ArrayType>) {
          e.varint(d.count);
        } else if constexpr (std::is_same_v<D, AggregateType>) {
          e.u8(static_cast<std::uint8_t>(d.kind));
          e.bytes(d.name);
          e.varint(d.size);
          e.varint(d.alignment);
          facts::encode(e, d.packed);
          facts::encode(e, d.complete);
          e.varint(d.fields.size());
          for (const Field &f : d.fields) {
            e.bytes(f.name);
            e.varint(f.bit_offset);
            e.varint(f.bit_size);
          }
        } else if constexpr (std::is_same_v<D, EnumType>) {
          e.bytes(d.name);
          e.varint(d.size);
          facts::encode(e, d.is_signed);
          facts::encode(e, d.complete);
          e.varint(d.values.size());
          for (const Enumerator &v : d.values) {
            e.bytes(v.name);
            e.svarint(v.value);
          }
        } else if constexpr (std::is_same_v<D, TypedefType>) {
          e.bytes(d.name);
        } else if constexpr (std::is_same_v<D, QualifiedType>) {
          e.u8(d.quals);
        } else if constexpr (std::is_same_v<D, FunctionType>) {
          e.varint(d.params.size());
          for (const Param &p : d.params) e.bytes(p.name);
          facts::encode(e, d.varargs);
          e.u8(static_cast<std::uint8_t>(d.cc));
        }
      },
      t.data);
}

template <class E>
E Enum(Decoder &d, E max) {
  std::uint8_t v = d.u8();
  if (v > static_cast<std::uint8_t>(max)) throw DecodeError("bad enum value in type record");
  return static_cast<E>(v);
}

Type DecodeData(Decoder &d) {
  const auto kind = Enum(d, Kind::Undefined);
  switch (kind) {
    case Kind::Void: return VoidType{};
    case Kind::Bool: return BoolType{facts::decode<std::uint32_t>(d)};
    case Kind::Undefined: return UndefinedType{facts::decode<std::uint32_t>(d)};
    case Kind::Int: {
      IntType t;
      t.size = facts::decode<std::uint32_t>(d);
      t.is_signed = facts::decode<bool>(d);
      t.rank = Enum(d, IntRank::Char32);
      return t;
    }
    case Kind::Float: {
      FloatType t;
      t.size = facts::decode<std::uint32_t>(d);
      t.kind = Enum(d, FloatKind::Float128);
      t.complex = facts::decode<bool>(d);
      return t;
    }
    case Kind::Pointer: {
      PointerType t;
      t.size = facts::decode<std::uint32_t>(d);
      t.kind = Enum(d, PointerKind::RValueRef);
      return t;
    }
    case Kind::Array: {
      ArrayType t;
      t.count = d.varint();
      return t;
    }
    case Kind::Aggregate: {
      AggregateType t;
      t.kind = Enum(d, AggregateKind::Union);
      t.name = d.bytes();
      t.size = d.varint();
      t.alignment = facts::decode<std::uint32_t>(d);
      t.packed = facts::decode<bool>(d);
      t.complete = facts::decode<bool>(d);
      const std::size_t n = d.count();
      for (std::size_t i = 0; i < n; ++i) {
        Field f;
        f.name = d.bytes();
        f.bit_offset = d.varint();
        f.bit_size = facts::decode<std::uint32_t>(d);
        t.fields.push_back(std::move(f));
      }
      return t;
    }
    case Kind::Enum: {
      EnumType t;
      t.name = d.bytes();
      t.size = facts::decode<std::uint32_t>(d);
      t.is_signed = facts::decode<bool>(d);
      t.complete = facts::decode<bool>(d);
      const std::size_t n = d.count();
      for (std::size_t i = 0; i < n; ++i) {
        Enumerator v;
        v.name = d.bytes();
        v.value = d.svarint();
        t.values.push_back(std::move(v));
      }
      return t;
    }
    case Kind::Typedef: {
      TypedefType t;
      t.name = d.bytes();
      return t;
    }
    case Kind::Qualified: {
      QualifiedType t;
      t.quals = d.u8();
      return t;
    }
    case Kind::Function: {
      FunctionType t;
      const std::size_t n = d.count();
      for (std::size_t i = 0; i < n; ++i) t.params.push_back(Param{std::string(d.bytes()), {}});
      t.varargs = facts::decode<bool>(d);
      t.cc = Enum(d, CallConv::Other);
      return t;
    }
  }
  throw DecodeError("bad type kind");
}

}  // namespace

std::string EncodeTypeRecord(const TypeStore &store, TypeId id) {
  Type t = store.get(id);
  Encoder e;
  EncodeData(e, t);
  std::vector<std::string> refs;
  for_each_ref(t, [&](TypeId &ref, EdgeKind) { refs.push_back(store.hash(ref).hex()); });
  facts::encode(e, refs);
  return std::move(e).str();
}

TypeRecord DecodeTypeRecord(std::string_view bytes) {
  Decoder d(bytes);
  TypeRecord r;
  r.type = DecodeData(d);
  r.refs = facts::decode<std::vector<std::string>>(d);
  d.expect_done();
  std::uint32_t i = 0;
  for_each_ref(r.type, [&](TypeId &ref, EdgeKind) { ref = TypeId::local(i++); });
  if (i != r.refs.size()) throw DecodeError("type record has the wrong number of references");
  return r;
}

std::string NamedTypeKey(const Type &t) {
  if (const auto *a = t.as<AggregateType>()) {
    if (a->name.empty()) return {};
    switch (a->kind) {
      case AggregateKind::Struct: return "struct " + a->name;
      case AggregateKind::Class: return "class " + a->name;
      case AggregateKind::Union: return "union " + a->name;
    }
  }
  if (const auto *e = t.as<EnumType>()) return e->name.empty() ? std::string() : "enum " + e->name;
  if (const auto *d = t.as<TypedefType>()) return d->name.empty() ? std::string() : "typedef " + d->name;
  return {};
}

std::optional<std::string> NormalizeTypeCategory(std::string_view path, std::string *error) {
  auto fail = [&](std::string why) -> std::optional<std::string> {
    if (error) *error = std::move(why);
    return std::nullopt;
  };
  if (path.empty() || path == "/") return std::string();
  if (path.size() > 1024) return fail("category path is longer than 1024 bytes");
  if (path.front() != '/') return fail("category path must start with '/'");
  std::string out;
  int levels = 0;
  std::size_t i = 1;
  while (i <= path.size()) {
    std::size_t j = path.find('/', i);
    if (j == std::string_view::npos) j = path.size();
    std::string_view part = path.substr(i, j - i);
    if (part.empty()) {
      if (j == path.size()) break;  // a trailing '/'
      return fail("category path has an empty part");
    }
    if (part == "." || part == "..") return fail("category path has a '.' or '..' part");
    for (char c : part)
      if (static_cast<unsigned char>(c) < 0x20 || c == 0x7f) return fail("category path has a control character");
    if (++levels > 32) return fail("category path is deeper than 32 levels");
    out += "/";
    out += part;
    i = j + 1;
  }
  return out;
}

bool IsNamedTypeKey(std::string_view key) {
  for (std::string_view kw : {"struct ", "union ", "class ", "enum ", "typedef "})
    if (key.starts_with(kw) && key.size() > kw.size() && key.size() <= 1024) return true;
  return false;
}

std::map<std::string, TypeId> InternRecords(const std::map<std::string, std::string> &records, TypeStore &store) {
  TypeGraph graph;
  std::map<std::string, TypeId> local;
  for (const auto &[hash, rec] : records) local.emplace(hash, graph.reserve());
  std::optional<TypeId> missing;
  for (const auto &[hash, rec] : records) {
    TypeRecord r;
    try {
      r = DecodeTypeRecord(rec);
    } catch (const DecodeError &) {
      r.type = UndefinedType{1};
      r.refs.clear();
    }
    for_each_ref(r.type, [&](TypeId &ref, EdgeKind) {
      auto it = local.find(RefHash(r, ref));
      if (it != local.end()) {
        ref = it->second;
      } else {
        if (!missing) missing = graph.add(UndefinedType{1});
        ref = *missing;
      }
    });
    graph.set(local.at(hash), std::move(r.type));
  }
  graph.break_invalid_cycles();
  std::vector<TypeId> ids = store.intern(graph);
  std::map<std::string, TypeId> out;
  for (const auto &[hash, l] : local) out.emplace(hash, ids[l.index()]);
  return out;
}

}  // namespace revkit::backend
