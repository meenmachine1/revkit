#include "library_types.h"

#include "type_record.h"

#include "revkit/facts/codec.h"
#include "revkit/types/store.h"

#include <algorithm>
#include <deque>
#include <map>
#include <set>

namespace revkit::backend {

using namespace revkit::types;
using inputs::GhidraArchive;

const std::string *LibraryTypes::record(const std::string &hash) const {
  auto it = std::lower_bound(records.begin(), records.end(), hash, [](const auto &r, const std::string &h) { return r.first < h; });
  return it != records.end() && it->first == hash ? &it->second : nullptr;
}

std::string LibraryTypes::archive_of(const std::string &hash) const {
  auto it = std::lower_bound(sources.begin(), sources.end(), hash, [](const auto &r, const std::string &h) { return r.first < h; });
  return it != sources.end() && it->first == hash ? it->second : archive;
}

void LibraryTypes::encode(facts::Encoder &e) const {
  e.bytes(archive);
  facts::encode(e, records);
  facts::encode(e, named);
  facts::encode(e, sources);
}

LibraryTypes LibraryTypes::decode(facts::Decoder &d) {
  LibraryTypes t;
  t.archive = d.bytes();
  t.records = facts::decode<std::vector<std::pair<std::string, std::string>>>(d);
  t.named = facts::decode<std::vector<std::pair<std::string, std::string>>>(d);
  t.sources = facts::decode<std::vector<std::pair<std::string, std::string>>>(d);
  return t;
}

namespace {

class Converter {
 public:
  Converter(const GhidraArchive &a, const inputs::DataOrg &org, bool char_signed) : a_(a), org_(org), char_signed_(char_signed) {}

  TypeId conv(std::uint64_t id, int depth = 0) {
    if (auto it = memo_.find(id); it != memo_.end()) return it->second;
    if (id == 0 || depth > 64) return undefined(1);
    switch (GhidraArchive::kind_of(id)) {
      case 0:
        if (const auto *b = a_.builtin(id)) return memo(id, g_.add(builtin(*b)));
        break;
      case 3:
        if (const auto *x = a_.array(id)) {
          TypeId l = memo(id, g_.reserve());
          g_.set(l, ArrayType{conv(x->element, depth + 1), static_cast<std::uint64_t>(std::max(0, x->count))});
          return l;
        }
        break;
      case 4:
        if (const auto *p = a_.pointer(id)) {
          TypeId l = memo(id, g_.reserve());
          const auto size = static_cast<std::uint32_t>(p->length > 0 ? p->length : static_cast<int>(org_.pointer));
          PointerType pt;
          pt.target = p->target == 0 ? undefined(1) : conv(p->target, depth + 1);
          pt.size = size;
          g_.set(l, pt);
          return l;
        }
        break;
      case 5:
        if (const auto *t = a_.typedef_(id)) {
          TypeId l = memo(id, g_.reserve());
          g_.set(l, TypedefType{t->name, conv(t->target, depth + 1)});
          return l;
        }
        break;
      case 1:
        if (const auto *c = a_.composite(id)) {
          TypeId l = memo(id, g_.reserve());
          AggregateType agg;
          agg.kind = c->is_union ? AggregateKind::Union : AggregateKind::Struct;
          agg.name = c->name;
          agg.size = static_cast<std::uint64_t>(std::max(0, c->length));
          agg.complete = c->length > 0;
          for (const GhidraArchive::Component &m : c->components) {
            if (m.type == 0 && m.name.empty()) continue;  // undefined filler
            Field f;
            f.name = m.name.empty() ? "field_0x" + Hex(m.offset) : m.name;
            f.type = conv(m.type, depth + 1);
            f.bit_offset = c->is_union ? 0 : static_cast<std::uint64_t>(m.offset) * 8;
            agg.fields.push_back(std::move(f));
          }
          g_.set(l, std::move(agg));
          return l;
        }
        break;
      case 8:
        if (const auto *e = a_.enumeration(id)) {
          EnumType et;
          et.name = e->name;
          et.size = static_cast<std::uint32_t>(e->size);
          for (const auto &[n, v] : e->values) {
            et.values.push_back({n, v});
            et.is_signed = et.is_signed || v < 0;
          }
          return memo(id, g_.add(std::move(et)));
        }
        break;
      case 6:
        if (const auto *fn = a_.function_type(id)) {
          TypeId l = memo(id, g_.reserve());
          FunctionType ft;
          ft.ret = fn->ret == 0 ? g_.add(VoidType{}) : conv(fn->ret, depth + 1);
          for (const GhidraArchive::Param &p : fn->params) ft.params.push_back({p.name, conv(p.type, depth + 1)});
          ft.varargs = fn->varargs;
          g_.set(l, std::move(ft));
          return l;
        }
        break;
      default: break;
    }
    return memo(id, undefined(1));
  }

  TypeGraph &graph() { return g_; }

 private:
  static std::string Hex(int v) {
    char buf[16];
    std::snprintf(buf, sizeof buf, "%x", v);
    return buf;
  }
  TypeId memo(std::uint64_t id, TypeId l) {
    memo_[id] = l;
    return l;
  }
  TypeId undefined(std::uint32_t n) { return g_.add(UndefinedType{n}); }

  Type builtin(const GhidraArchive::Builtin &b) const {
    const std::string cls = b.class_name.substr(b.class_name.rfind('.') + 1);
    auto i = [](std::uint32_t size, bool s, IntRank r) { return Type(IntType{size, s, r}); };
    if (cls == "CharDataType") return i(1, char_signed_, IntRank::PlainChar);
    if (cls == "SignedCharDataType") return i(1, true, IntRank::Char);
    if (cls == "UnsignedCharDataType") return i(1, false, IntRank::Char);
    if (cls == "ShortDataType") return i(org_.shrt, true, IntRank::Short);
    if (cls == "UnsignedShortDataType") return i(org_.shrt, false, IntRank::Short);
    if (cls == "IntegerDataType") return i(org_.integer, true, IntRank::Int);
    if (cls == "UnsignedIntegerDataType") return i(org_.integer, false, IntRank::Int);
    if (cls == "LongDataType") return i(org_.lng, true, IntRank::Long);
    if (cls == "UnsignedLongDataType") return i(org_.lng, false, IntRank::Long);
    if (cls == "LongLongDataType") return i(org_.longlong, true, IntRank::LongLong);
    if (cls == "UnsignedLongLongDataType") return i(org_.longlong, false, IntRank::LongLong);
    if (cls == "WideCharDataType") return i(org_.wchar, org_.wchar == 4, IntRank::WChar);
    if (cls == "WideChar16DataType") return i(2, false, IntRank::Char16);
    if (cls == "WideChar32DataType") return i(4, false, IntRank::Char32);
    if (cls == "BooleanDataType") return BoolType{1};
    if (cls == "FloatDataType") return FloatType{4, FloatKind::Float};
    if (cls == "DoubleDataType") return FloatType{8, FloatKind::Double};
    if (cls == "LongDoubleDataType") return FloatType{org_.long_double_aligned, FloatKind::LongDouble};
    if (cls == "VoidDataType") return VoidType{};
    if (cls == "ByteDataType") return i(1, false, IntRank::Fixed);
    if (cls == "WordDataType") return i(2, false, IntRank::Fixed);
    if (cls == "DWordDataType") return i(4, false, IntRank::Fixed);
    if (cls == "QWordDataType") return i(8, false, IntRank::Fixed);
    if (cls == "SignedByteDataType") return i(1, true, IntRank::Fixed);
    if (cls == "SignedWordDataType") return i(2, true, IntRank::Fixed);
    if (cls == "SignedDWordDataType") return i(4, true, IntRank::Fixed);
    if (cls == "SignedQWordDataType") return i(8, true, IntRank::Fixed);
    if (cls.starts_with("Undefined") && cls.ends_with("DataType")) {
      const std::string n = cls.substr(9, cls.size() - 9 - 8);
      if (!n.empty() && std::all_of(n.begin(), n.end(), ::isdigit)) return UndefinedType{static_cast<std::uint32_t>(std::stoul(n))};
    }
    return UndefinedType{1};
  }

  const GhidraArchive &a_;
  inputs::DataOrg org_;
  bool char_signed_;
  TypeGraph g_;
  std::map<std::uint64_t, TypeId> memo_;
};

}  // namespace

LibraryTypes ConvertArchive(const GhidraArchive &archive, const std::string &name, const inputs::DataOrg &org,
                            bool char_signed) {
  Converter c(archive, org, char_signed);
  std::vector<TypeId> roots;
  for (const auto &[id, x] : archive.composites())
    if (!x.name.empty()) roots.push_back(c.conv(id));
  for (const auto &[id, x] : archive.enums())
    if (!x.name.empty()) roots.push_back(c.conv(id));
  for (const auto &[id, x] : archive.typedefs())
    if (!x.name.empty()) roots.push_back(c.conv(id));
  TypeGraph &g = c.graph();
  g.break_invalid_cycles();
  TypeStore store;
  std::vector<TypeId> ids = store.intern(g);
  LibraryTypes out;
  out.archive = name;
  std::map<std::string, std::string> records, named;
  std::vector<TypeId> work;
  std::set<TypeId> seen;
  for (TypeId r : roots) {
    TypeId id = ids[r.index()];
    std::string key = NamedTypeKey(store.get(id));
    if (!key.empty()) named.emplace(std::move(key), store.hash(id).hex());
    if (seen.insert(id).second) work.push_back(id);
  }
  while (!work.empty()) {
    TypeId id = work.back();
    work.pop_back();
    records.emplace(store.hash(id).hex(), EncodeTypeRecord(store, id));
    Type t = store.get(id);
    for_each_ref(t, [&](TypeId &ref, EdgeKind) {
      if (seen.insert(ref).second) work.push_back(ref);
    });
  }
  out.records.assign(records.begin(), records.end());
  out.named.assign(named.begin(), named.end());
  return out;
}

LibraryTypes ConvertLibrary(const inputs::LibraryPrototypes &lib) {
  LibraryTypes out;
  for (std::size_t i = 0; i < lib.archives.size(); ++i) out.archive += (i ? "," : "") + lib.archives[i];
  std::map<std::string, std::string> records, named, sources;
  std::deque<std::pair<TypeId, std::string>> work;  // with the archive that reached it
  std::set<TypeId> seen;
  auto root = [&](TypeId id, const std::string &archive) {
    if (seen.insert(id).second) work.emplace_back(id, archive);
  };
  for (const auto &n : lib.named) {
    std::string key = NamedTypeKey(lib.store.get(n.id));
    if (!key.empty()) named.emplace(std::move(key), lib.store.hash(n.id).hex());
    std::string archive = n.where.file;
    if (archive.ends_with(".h")) archive.resize(archive.size() - 2);
    root(n.id, archive);
  }
  for (const auto &[name, f] : lib.functions) root(f.type, f.archive);
  while (!work.empty()) {
    auto [id, archive] = work.front();
    work.pop_front();
    const std::string hash = lib.store.hash(id).hex();
    records.emplace(hash, EncodeTypeRecord(lib.store, id));
    sources.emplace(hash, archive);
    Type t = lib.store.get(id);
    for_each_ref(t, [&](TypeId &ref, EdgeKind) {
      if (seen.insert(ref).second) work.emplace_back(ref, archive);
    });
  }
  out.records.assign(records.begin(), records.end());
  out.named.assign(named.begin(), named.end());
  out.sources.assign(sources.begin(), sources.end());
  return out;
}

void MergeLibraryTypes(LibraryTypes &into, const LibraryTypes &extra) {
  std::map<std::string, std::string> named(into.named.begin(), into.named.end());
  std::map<std::string, std::string> records(into.records.begin(), into.records.end());
  for (const auto &[key, hash] : extra.named) named.try_emplace(key, hash);
  std::map<std::string, std::string> sources(into.sources.begin(), into.sources.end());
  for (const auto &[hash, rec] : extra.records)
    if (records.try_emplace(hash, rec).second) sources.emplace(hash, extra.archive_of(hash));
  into.named.assign(named.begin(), named.end());
  into.records.assign(records.begin(), records.end());
  into.sources.assign(sources.begin(), sources.end());
  if (!extra.archive.empty()) into.archive += (into.archive.empty() ? "" : ",") + extra.archive;
}

}  // namespace revkit::backend
