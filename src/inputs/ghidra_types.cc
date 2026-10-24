#include "revkit/inputs/ghidra_types.h"

#include "revkit/types/describe.h"

#include "revkit/inputs/demangled.h"
#include "revkit/lift/abi.hh"

#include <algorithm>
#include <regex>
#include <set>

namespace revkit::inputs {

namespace {

using lift::DecompElement;
using Attrs = std::vector<std::pair<std::string, DecompElement::Value>>;

constexpr std::uint64_t kBuiltin = 0xc000000000000000ULL;
// Ids by kind of type, in ranges of their own (Ghidra's database ids for
// the kinds, plus a bit no Ghidra id sets, so the two never collide).
constexpr std::uint64_t kOwn = 0x0040000000000000ULL;
constexpr std::uint64_t kStructBase = 0x0100000000000000ULL | kOwn;
constexpr std::uint64_t kTypedefBase = 0x0500000000000000ULL | kOwn;
constexpr std::uint64_t kFunctionBase = 0x0600000000000000ULL | kOwn;
constexpr std::uint64_t kEnumBase = 0x0800000000000000ULL | kOwn;

// Ids from content, so every encoder (one per program, per function or per
// overlay) gives a type the same id.
std::uint64_t id_of(std::uint64_t base, const types::Hash &h) {
  std::uint64_t v = 0;
  for (int i = 0; i < 6; ++i) v = v << 8 | h.bytes[static_cast<std::size_t>(i)];
  return base | v;
}
std::uint64_t id_of(std::uint64_t base, const std::string &key) {
  std::uint64_t v = 0xcbf29ce484222325ULL;  // FNV-1a
  for (unsigned char c : key) v = (v ^ c) * 0x100000001b3ULL;
  return base | (v & 0x0000ffffffffffffULL);
}

}  // namespace

std::uint64_t aggregate_id(std::string_view hash_hex) {
  if (hash_hex.size() < 12) return 0;
  std::uint64_t v = 0;
  for (char c : hash_hex.substr(0, 12)) {
    const int d = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
    if (d < 0) return 0;
    v = v << 4 | static_cast<std::uint64_t>(d);
  }
  return kStructBase | v;
}

namespace {

struct Builtin {
  const char *name;
  std::uint8_t id;
  const char *meta;
  int size;  // 0: from the data organization
  bool is_char = false;
  bool utf = false;
};

// Ghidra's built-in data types the decompiler sees (PcodeDataTypeManager),
// with their ids.
const Builtin kBuiltins[] = {
    {"undefined", 0x00, "unknown", 1},  {"undefined1", 0xb4, "unknown", 1}, {"undefined2", 0xb5, "unknown", 2},
    {"undefined3", 0xb6, "unknown", 3}, {"undefined4", 0xb7, "unknown", 4}, {"undefined5", 0xb8, "unknown", 5},
    {"undefined6", 0xb9, "unknown", 6}, {"undefined7", 0xba, "unknown", 7}, {"undefined8", 0xbb, "unknown", 8},
    {"byte", 0x7a, "uint", 1},          {"word", 0xce, "uint", 2},          {"uint3", 0xc0, "uint", 3},
    {"dword", 0x7f, "uint", 4},         {"uint5", 0xc1, "uint", 5},         {"uint6", 0xc2, "uint", 6},
    {"uint7", 0xc3, "uint", 7},         {"qword", 0xa2, "uint", 8},         {"uint16", 0xbf, "uint", 16},
    {"sbyte", 0xa9, "int", 1},          {"sword", 0xaf, "int", 2},          {"int3", 0x91, "int", 3},
    {"sdword", 0xab, "int", 4},         {"int5", 0x92, "int", 5},           {"int6", 0x93, "int", 6},
    {"int7", 0x94, "int", 7},           {"sqword", 0xad, "int", 8},         {"int16", 0x90, "int", 16},
    {"char", 0x7b, "int", 1, true},     {"uchar", 0xbe, "uint", 1, true},   {"schar", 0xaa, "int", 1, true},
    {"short", 0xa8, "int", 0},          {"ushort", 0xc8, "uint", 0},        {"int", 0x95, "int", 0},
    {"uint", 0xc4, "uint", 0},          {"long", 0x97, "int", 0},           {"ulong", 0xc6, "uint", 0},
    {"longlong", 0x9a, "int", 0},       {"ulonglong", 0xc7, "uint", 0},     {"float2", 0x86, "float", 2},
    {"float", 0x8a, "float", 4},        {"double", 0x82, "float", 8},       {"float10", 0x84, "float", 10},
    {"float16", 0x85, "float", 16},     {"longdouble", 0x99, "float", 0},   {"bool", 0x79, "bool", 1},
    {"wchar_t", 0xcd, "int", 0, false, true}, {"wchar16", 0xcb, "int", 2, false, true},
    {"wchar32", 0xcc, "int", 4, false, true},
};

const Builtin *find_builtin(const std::string &name) {
  for (const Builtin &b : kBuiltins)
    if (name == b.name) return &b;
  return nullptr;
}

// DWARFDataTypeManager.initBaseDataTypes: DWARF base type spellings Ghidra
// maps to its own types directly.
const std::map<std::string, std::string> &spelling_map() {
  static const std::map<std::string, std::string> m = {
      {"char", "char"},
      {"signed char", "char"},
      {"unsigned char", "uchar"},
      {"short", "short"},
      {"short int", "short"},
      {"signed short int", "short"},
      {"unsigned short int", "ushort"},
      {"short unsigned int", "ushort"},
      {"int", "int"},
      {"signed int", "int"},
      {"unsigned int", "uint"},
      {"long", "long"},
      {"long int", "long"},
      {"signed long int", "long"},
      {"unsigned long int", "ulong"},
      {"long unsigned int", "ulong"},
      {"long long", "longlong"},
      {"long long int", "longlong"},
      {"signed long long int", "longlong"},
      {"unsigned long long int", "ulonglong"},
      {"long long unsigned int", "ulonglong"},
      {"double", "double"},
      {"long double", "longdouble"},
      {"float", "float"},
      {"bool", "bool"},
      {"wchar_t", "wchar_t"},
      {"void", "void"},
  };
  return m;
}

DecompElement el(std::string tag, Attrs attrs = {}, std::vector<DecompElement> kids = {}) {
  return DecompElement{std::move(tag), std::move(attrs), std::move(kids)};
}

// The type of a base type or a typedef chain down to one, or invalid.
struct BaseInfo {
  bool valid = false;
  bool is_float = false, is_bool = false, is_signed = false, is_char = false, utf = false;
  std::uint64_t size = 0;
};

}  // namespace

DataOrg data_org(const loader::Image &image, const std::string &language_id) {
  DataOrg o;
  o.pointer = image.bits / 8;
  o.big_endian = language_id.find(":BE:") != std::string::npos;
  const bool x86 = language_id.starts_with("x86:");
  const bool pe = image.format == loader::Format::pe;
  if (x86 && image.bits == 64) {
    o.extrapop = 8;
    if (pe) {
      o.lng = 4;
      o.wchar = 2;
      o.long_double = o.long_double_aligned = 8;
    } else {
      o.wchar = 4;
      o.long_double = 10;
      o.long_double_aligned = 16;
    }
  } else if (x86) {
    o.extrapop = 4;
    o.lng = 4;
    o.longlong = 8;
    o.wchar = pe ? 2 : 4;
    o.long_double = pe ? 8 : 10;
    o.long_double_aligned = pe ? 8 : 12;
  } else if (language_id.starts_with("AARCH64:")) {
    o.wchar = 4;
  } else if (image.bits == 32) {
    o.lng = 4;
  }
  // Go's specs (x86-64-golang.cspec, AARCH64_golang.cspec: an 8-byte int;
  // x86-32-golang.cspec: an 8-byte long) say their own sizes, as the
  // decompiler's core types take them (docs/go.md).
  if (language_id.ends_with(":golang")) {
    try {
      const lift::DataOrganization d =
          lift::read_data_organization(language_id.substr(0, language_id.size() - 7), "golang");
      auto take = [&](const char *key, unsigned &to) {
        if (auto it = d.values.find(key); it != d.values.end() && it->second > 0) to = static_cast<unsigned>(it->second);
      };
      take("short_size", o.shrt);
      take("integer_size", o.integer);
      take("long_size", o.lng);
      take("long_long_size", o.longlong);
      take("wchar_size", o.wchar);
    } catch (const std::exception &) {
    }
  }
  return o;
}

GhidraTypes::GhidraTypes(const types::TypeStore &store, DataOrg org,
                         const std::map<types::TypeId, std::string> *base_names)
    : store_(store), org_(org), base_names_(base_names) {}

DecompElement GhidraTypes::builtin(const std::string &name) const { return builtin_type(name, org_); }

// The size of a built-in whose size the data organization says (Ghidra's
// IntegerDataType, ShortDataType, LongDataType... take theirs from it).
static unsigned sized(std::string_view name, const DataOrg &org) {
  if (name == "long" || name == "ulong") return org.lng;
  if (name == "int" || name == "uint") return org.integer;
  if (name == "short" || name == "ushort") return org.shrt;
  if (name == "longlong" || name == "ulonglong") return org.longlong;
  if (name == "longdouble") return org.long_double;
  return org.wchar;
}

DecompElement builtin_type(const std::string &name, const DataOrg &org_) {
  if (name == "void") return el("void");
  const Builtin *b = find_builtin(name);
  if (b == nullptr) b = find_builtin("undefined");
  int size = b->size;
  if (size == 0) size = static_cast<int>(sized(b->name, org_));
  Attrs a;
  if (b->is_char) a.emplace_back("char", true);
  a.emplace_back("id", kBuiltin | b->id);
  a.emplace_back("metatype", std::string(b->meta));
  a.emplace_back("name", std::string(b->name));
  a.emplace_back("size", std::int64_t{size});
  if (b->utf) a.emplace_back("utf", true);
  if (std::string(b->meta) == "unknown") return el("typeref", {{"id", kBuiltin | b->id}, {"name", std::string(b->name)}});
  return el("type", std::move(a));
}

DecompElement GhidraTypes::typeref(const Named &n) const {
  Attrs a{{"id", n.id}, {"name", n.name}};
  if (n.size != 0) a.emplace_back("size", std::int64_t{n.size});
  return el("typeref", std::move(a));
}

std::uint64_t GhidraTypes::size(types::TypeId id) const { return store_.size_of(id); }

std::vector<DecompElement> GhidraTypes::take_definitions() { return std::exchange(defs_, {}); }

std::string GhidraTypes::spelling(types::TypeId id) const {
  if (base_names_ != nullptr)
    if (auto it = base_names_->find(id); it != base_names_->end() && !it->second.empty()) return it->second;
  // No spelling recorded (PDB, or a type the reader made up): the C one.
  const types::Type &t = store_.get(id);
  if (const auto *i = t.as<types::IntType>()) {
    using types::IntRank;
    const char *u = i->is_signed ? "" : "unsigned ";
    switch (i->rank) {
      case IntRank::PlainChar: return "char";
      case IntRank::Char: return i->is_signed ? "signed char" : "unsigned char";
      case IntRank::Short: return i->is_signed ? "short" : "unsigned short int";
      case IntRank::Int: return i->is_signed ? "int" : "unsigned int";
      case IntRank::Long: return i->is_signed ? "long" : "unsigned long int";
      case IntRank::LongLong: return i->is_signed ? "long long" : "unsigned long long int";
      case IntRank::WChar: return "wchar_t";
      case IntRank::Char8: return "char8_t";
      case IntRank::Char16: return "char16_t";
      case IntRank::Char32: return "char32_t";
      case IntRank::Int128: return std::string(u) + "__int128";
      default: return "";
    }
  }
  if (const auto *f = t.as<types::FloatType>()) {
    switch (f->kind) {
      case types::FloatKind::Float: return "float";
      case types::FloatKind::Double: return "double";
      case types::FloatKind::LongDouble: return "long double";
      default: return "";
    }
  }
  if (t.as<types::BoolType>()) return "_Bool";
  return "";
}

// AbstractIntegerDataType.getSignedDataType / getUnsignedDataType and
// AbstractFloatDataType.getFloatDataType: generic types by size, the data
// organization's C types unless the size is explicit.
std::string GhidraTypes::generic_name(bool is_float, bool is_signed, bool is_char, std::uint64_t size,
                                      bool fixed) const {
  if (is_char) return is_signed ? "char" : "uchar";
  if (is_float) {
    if (!fixed) {
      if (size == 4) return "float";
      if (size == 8) return "double";
      if (size == org_.long_double) return "longdouble";
    }
    switch (size) {
      case 2: return "float2";
      case 4: return "float";
      case 8: return "double";
      case 10: return "float10";
      case 16: return "float16";
      default: return "";
    }
  }
  if (size == 16) return is_signed ? "int16" : "uint16";
  if (size == 0 || size > 8) return "";
  if (!fixed) {
    if (size == org_.integer) return is_signed ? "int" : "uint";
    if (size == org_.shrt) return is_signed ? "short" : "ushort";
    if (size == org_.lng) return is_signed ? "long" : "ulong";
    if (size == org_.longlong) return is_signed ? "longlong" : "ulonglong";
  }
  static const char *const s[] = {"sbyte", "sword", "int3", "sdword", "int5", "int6", "int7", "sqword"};
  static const char *const u[] = {"byte", "word", "uint3", "dword", "uint5", "uint6", "uint7", "qword"};
  return (is_signed ? s : u)[size - 1];
}

namespace {

// DWARFDataTypeManager.FIXED_SIZED_TYPE_NAME_PATTERN: a name that says its
// bits (int32_t, __uint64_t).
int explicit_bits(const std::string &name) {
  static const std::regex re("\\D+(8|16|32|64|128)\\D*");
  std::smatch m;
  if (!std::regex_match(name, m, re)) return -1;
  return std::stoi(m[1].str());
}

}  // namespace

DecompElement GhidraTypes::named_typedef(const std::string &name, DecompElement target, std::uint64_t key) {
  auto it = spelled_.find(name + "#" + std::to_string(key));
  if (it == spelled_.end()) {
    Named n{id_of(kTypedefBase, name + "#" + std::to_string(key)), name, 0};
    defs_.push_back(el("def", {{"id", n.id}, {"name", name}}, {std::move(target)}));
    it = spelled_.emplace(name + "#" + std::to_string(key), n).first;
  }
  return typeref(it->second);
}

// DWARFDataTypeManager.getBaseType(name, size, encoding).
DecompElement GhidraTypes::generic(bool is_float, bool is_signed, bool is_char, std::uint64_t size,
                                   const std::string &spelling) {
  if (!spelling.empty()) {
    auto m = spelling_map().find(spelling);
    if (m != spelling_map().end()) {
      const Builtin *b = find_builtin(m->second);
      std::uint64_t bsize = 0;
      if (b != nullptr) {
        bsize = static_cast<std::uint64_t>(b->size);
        if (m->second == "longdouble") bsize = org_.long_double_aligned;
        else if (bsize == 0) bsize = sized(m->second, org_);
      }
      const bool signed_type = b != nullptr && std::string(b->meta) == "int";
      const bool integer = b != nullptr && (std::string(b->meta) == "int" || std::string(b->meta) == "uint");
      const bool compatible = is_char || !integer || signed_type == is_signed;
      if (b != nullptr && bsize == size && compatible) return builtin(m->second);
    }
  }
  const int bits = explicit_bits(spelling);
  const bool fixed = bits != -1 && static_cast<std::uint64_t>(bits / 8) == size;
  std::string g = generic_name(is_float, is_signed, is_char, size, fixed);
  DecompElement target = g.empty() ? builtin(size >= 1 && size <= 8 ? "undefined" + std::to_string(size) : "undefined")
                                   : builtin(g);
  if (spelling.empty()) return target;
  const std::uint64_t key = (size << 8) | (is_float ? 1 : 0) | (is_signed ? 2 : 0) | (is_char ? 4 : 0);
  return named_typedef(spelling, std::move(target), key);
}

DecompElement GhidraTypes::base(types::TypeId id, const std::string &sp) {
  const types::Type &t = store_.get(id);
  if (const auto *i = t.as<types::IntType>()) {
    const bool is_char = i->rank == types::IntRank::PlainChar || i->rank == types::IntRank::Char;
    if (i->rank == types::IntRank::Char16 || i->rank == types::IntRank::Char32) {
      DecompElement w = builtin(i->size == 2 ? "wchar16" : "wchar32");
      return sp.empty() ? w : named_typedef(sp, std::move(w), (i->size << 8) | 8);
    }
    return generic(false, i->is_signed, is_char, i->size, sp);
  }
  if (const auto *f = t.as<types::FloatType>()) return generic(true, true, false, f->size, sp);
  if (const auto *b = t.as<types::BoolType>()) {
    if (b->size == 1) {
      DecompElement bt = builtin("bool");
      return sp.empty() || sp == "bool" ? bt : named_typedef(sp, std::move(bt), 0x100);
    }
    return generic(false, false, false, b->size, sp);
  }
  return builtin("undefined");
}

DecompElement GhidraTypes::ref(types::TypeId id) {
  if (!id.valid()) return builtin("undefined");
  if (depth_ > 64) return builtin("undefined");
  struct Depth {
    int &d;
    explicit Depth(int &x) : d(x) { ++d; }
    ~Depth() { --d; }
  } guard(depth_);
  const types::Type &t = store_.get(id);
  switch (t.kind()) {
    case types::Kind::Void: return el("void");
    case types::Kind::Bool:
    case types::Kind::Int:
    case types::Kind::Float: return base(id, spelling(id));
    case types::Kind::Undefined: {
      std::uint32_t n = t.as<types::UndefinedType>()->size;
      if (n >= 1 && n <= 8) return builtin("undefined" + std::to_string(n));
      return el("type",
                {{"arraysize", std::int64_t{n}}, {"metatype", std::string("array")}, {"name", std::string()},
                 {"size", std::int64_t{n}}},
                {builtin("undefined1")});
    }
    case types::Kind::Qualified: return ref(t.as<types::QualifiedType>()->target);
    case types::Kind::Pointer: {
      const auto *p = t.as<types::PointerType>();
      return el("type",
                {{"metatype", std::string("ptr")}, {"name", std::string()}, {"size", std::int64_t{p->size}}},
                {ref(p->target)});
    }
    case types::Kind::Array: {
      const auto *a = t.as<types::ArrayType>();
      DecompElement elem = ref(a->element);
      const std::uint64_t esize = store_.size_of(a->element);
      if (a->count == 0 || esize == 0) {
        // A flexible or unknown-bound array: Ghidra's zero-length array
        // isn't a decompiler type; a pointer is how it decays anyway.
        return el("type",
                  {{"metatype", std::string("ptr")}, {"name", std::string()}, {"size", std::int64_t{org_.pointer}}},
                  {std::move(elem)});
      }
      return el("type",
                {{"arraysize", static_cast<std::int64_t>(a->count)},
                 {"metatype", std::string("array")},
                 {"name", std::string()},
                 {"size", static_cast<std::int64_t>(a->count * esize)}},
                {std::move(elem)});
    }
    case types::Kind::Typedef: {
      const auto *td = t.as<types::TypedefType>();
      if (auto it = named_.find(id); it != named_.end()) return typeref(it->second);
      // A typedef of a base type is Ghidra's type for the typedef's name
      // (DWARFDataTypeImporter.makeDataTypeForTypedef -> makeNamedBaseType).
      types::TypeId under = td->target;
      const types::Type *ut = &store_.get(under);
      while (const auto *q = ut->as<types::QualifiedType>()) {
        under = q->target;
        ut = &store_.get(under);
      }
      if (ut->kind() == types::Kind::Int || ut->kind() == types::Kind::Float || ut->kind() == types::Kind::Bool)
        return base(under, td->name);
      // typedef struct foo foo: the struct itself (elided, same name).
      if (const auto *a = ut->as<types::AggregateType>(); a && a->name == td->name) return ref(under);
      if (const auto *e = ut->as<types::EnumType>(); e && e->name == td->name) return ref(under);
      Named n{id_of(kTypedefBase, store_.hash(id)), td->name, 0};
      named_.emplace(id, n);
      DecompElement target = ref(td->target);
      defs_.push_back(el("def", {{"id", n.id}, {"name", n.name}}, {std::move(target)}));
      return typeref(n);
    }
    case types::Kind::Aggregate: return aggregate(id, *t.as<types::AggregateType>());
    case types::Kind::Enum: return enumeration(id, *t.as<types::EnumType>());
    case types::Kind::Function: return function(id, *t.as<types::FunctionType>());
  }
  return builtin("undefined");
}

DecompElement GhidraTypes::aggregate(types::TypeId id, const types::AggregateType &a) {
  if (auto it = named_.find(id); it != named_.end()) return typeref(it->second);
  const bool is_union = a.kind == types::AggregateKind::Union;
  std::string name = a.name;
  if (name.empty()) name = std::string(is_union ? "anon_union_" : "anon_struct_") + std::to_string(a.size);
  name = split_qualified(name).back();
  Named n{id_of(kStructBase, store_.hash(id)), name, 0};
  named_.emplace(id, n);
  std::vector<DecompElement> fields;
  // The fields it can lay out (types::decompiler_fields, which a header
  // for its C writes the same way: ExportC's).
  for (const types::DecompilerField &d : types::decompiler_fields(store_, a)) {
    const types::Field &f = a.fields[d.index];
    const auto ordinal = static_cast<std::int64_t>(d.index);
    if (f.bit_size != 0) {
      // A bitfield as the decompiler's <bitfield>: the byte offset of its
      // container (the bytes it spans) and its least significant bit
      // there. Bits count in memory order (from the least significant end
      // of a little-endian unit, the most significant of a big-endian
      // one), as cparse and DWARF lay them out.
      const std::uint64_t first_byte = f.bit_offset / 8;
      const std::uint64_t span = (f.bit_offset % 8 + f.bit_size + 7) / 8;
      const std::uint64_t lsb = org_.big_endian ? span * 8 - (f.bit_offset % 8 + f.bit_size) : f.bit_offset % 8;
      fields.push_back(el("bitfield",
                          {{"first", static_cast<std::int64_t>(lsb)},
                           {"id", ordinal},
                           {"name", f.name},
                           {"offset", static_cast<std::int64_t>(first_byte)},
                           {"size", static_cast<std::int64_t>(f.bit_size)}},
                          {ref(f.type)}));
      continue;
    }
    Attrs fa;
    if (is_union) fa.emplace_back("id", ordinal);
    fa.emplace_back("name", d.name);
    fa.emplace_back("offset", static_cast<std::int64_t>(is_union ? 0 : f.bit_offset / 8));
    fields.push_back(el("field", std::move(fa), {ref(f.type)}));
  }
  const std::uint64_t size = a.complete && a.size != 0 ? a.size : 1;
  std::uint32_t align = a.complete && a.size != 0 ? std::max<std::uint32_t>(1, store_.align_of(id)) : 1;
  if (a.packed) align = 1;
  defs_.push_back(el("type",
                     {{"alignment", std::int64_t{align}},
                      {"id", n.id},
                      {"metatype", std::string(is_union ? "union" : "struct")},
                      {"name", n.name},
                      {"size", static_cast<std::int64_t>(size)}},
                     std::move(fields)));
  return typeref(n);
}

DecompElement GhidraTypes::enumeration(types::TypeId id, const types::EnumType &e) {
  if (auto it = named_.find(id); it != named_.end()) return typeref(it->second);
  std::string name = e.name.empty() ? "anon_enum_" + std::to_string(e.size * 8) : e.name;
  name = split_qualified(name).back();
  Named n{id_of(kEnumBase, store_.hash(id)), name, 0};
  named_.emplace(id, n);
  bool negative = false;
  std::vector<DecompElement> vals;
  for (const types::Enumerator &v : e.values) {
    negative = negative || v.value < 0;
    vals.push_back(el("val", {{"name", v.name}, {"value", v.value}}));
  }
  const std::uint32_t size = e.size == 0 ? 1 : e.size;
  defs_.push_back(el("type",
                     {{"id", n.id},
                      {"metatype", std::string(negative ? "enum_int" : "enum_uint")},
                      {"name", n.name},
                      {"size", std::int64_t{size}}},
                     std::move(vals)));
  return typeref(n);
}

// An unnamed function type: Ghidra's FunctionDefinition named by
// DataTypeNamingUtil (_func_<return>_<param>..._varargs).
DecompElement GhidraTypes::function(types::TypeId id, const types::FunctionType &f) {
  if (auto it = named_.find(id); it != named_.end()) return typeref(it->second);
  std::string name = "_func_" + name_part(f.ret);
  for (const types::Param &p : f.params) name += "_" + name_part(p.type);
  if (f.varargs) name += "_varargs";
  Named n{id_of(kFunctionBase, store_.hash(id)), name, 1};
  named_.emplace(id, n);
  // A function definition's calling convention, as Java encodes its
  // getCallingConventionName(): only __thiscall is told (virtual methods'
  // pointers, docs/pe.md); others stay "unknown", as the debug info's
  // function types always were.
  const std::string model = f.cc == types::CallConv::Thiscall ? "__thiscall" : "unknown";
  Attrs pa{{"extrapop", std::int64_t{org_.extrapop}}, {"model", model}, {"modellock", true}};
  if (f.varargs) pa.emplace_back("dotdotdot", true);
  if (f.params.empty()) pa.emplace_back("voidlock", true);
  std::vector<DecompElement> params;
  for (const types::Param &p : f.params)
    params.push_back(el("param", {{"namelock", false}, {"typelock", true}}, {el("addr"), ref(p.type)}));
  DecompElement proto = el("prototype", std::move(pa),
                           {el("returnsym", {{"typelock", true}}, {el("addr"), ref(f.ret)}),
                            el("internallist", {}, std::move(params))});
  defs_.push_back(el("type",
                     {{"id", n.id}, {"metatype", std::string("code")}, {"name", name}, {"size", std::int64_t{1}}},
                     {std::move(proto)}));
  return typeref(n);
}

std::string GhidraTypes::name_part(types::TypeId id) {
  std::string s = name(id);
  std::string out;
  for (char c : s) {
    if (c == ' ') out += '_';
    else if (c == '*') out += "ptr";
    else out += c;
  }
  return out;
}

// Ghidra's display name: what a reference to the type is called.
std::string GhidraTypes::name(types::TypeId id) {
  if (auto it = names_.find(id); it != names_.end()) return it->second;
  DecompElement r = ref(id);
  std::string out;
  std::function<std::string(const DecompElement &)> show = [&](const DecompElement &e) -> std::string {
    if (e.tag == "void") return "void";
    const auto *n = e.attr("name");
    std::string nm = n ? std::get<std::string>(*n) : std::string();
    if (e.tag == "typeref" || e.tag == "def" || !nm.empty()) return nm;
    const auto *m = e.attr("metatype");
    std::string meta = m ? std::get<std::string>(*m) : std::string();
    if (meta == "ptr") return (e.children.empty() ? std::string("void") : show(e.children[0])) + " *";
    if (meta == "array") {
      const auto *c = e.attr("arraysize");
      return (e.children.empty() ? std::string("undefined") : show(e.children[0])) + "[" +
             std::to_string(c ? std::get<std::int64_t>(*c) : 0) + "]";
    }
    return nm;
  };
  out = show(r);
  names_.emplace(id, out);
  return out;
}

}  // namespace revkit::inputs
