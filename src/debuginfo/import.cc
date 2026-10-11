// DWARF DIEs to revkit types, functions and variables.

#include "die.h"
#include "dwarf_constants.h"
#include "revkit/debuginfo/dwarf.h"
#include "revkit/types/packing.h"

#include <algorithm>
#include <limits>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace revkit::debuginfo {
namespace {

using types::TypeId;

// Bounds on attribute chains (specification/abstract_origin, typedef
// chains, scope nesting) so malformed input can't loop.
constexpr int kMaxChain = 16;

bool is_type_tag(std::uint16_t tag) {
  switch (tag) {
    case dw::TAG_array_type:
    case dw::TAG_class_type:
    case dw::TAG_enumeration_type:
    case dw::TAG_pointer_type:
    case dw::TAG_reference_type:
    case dw::TAG_string_type:
    case dw::TAG_structure_type:
    case dw::TAG_subroutine_type:
    case dw::TAG_typedef:
    case dw::TAG_union_type:
    case dw::TAG_ptr_to_member_type:
    case dw::TAG_set_type:
    case dw::TAG_base_type:
    case dw::TAG_const_type:
    case dw::TAG_file_type:
    case dw::TAG_volatile_type:
    case dw::TAG_restrict_type:
    case dw::TAG_unspecified_type:
    case dw::TAG_rvalue_reference_type:
    case dw::TAG_atomic_type:
    case dw::TAG_immutable_type: return true;
    default: return false;
  }
}

bool is_aggregate_tag(std::uint16_t tag) {
  return tag == dw::TAG_structure_type || tag == dw::TAG_class_type || tag == dw::TAG_union_type;
}

bool contains(std::string_view s, std::string_view w) { return s.find(w) != std::string_view::npos; }

types::IntRank rank_from_name(std::string_view n) {
  using types::IntRank;
  if (n == "char") return IntRank::PlainChar;
  if (contains(n, "wchar_t")) return IntRank::WChar;
  if (contains(n, "char8_t")) return IntRank::Char8;
  if (contains(n, "char16_t")) return IntRank::Char16;
  if (contains(n, "char32_t")) return IntRank::Char32;
  if (contains(n, "char")) return IntRank::Char;
  if (contains(n, "__int128")) return IntRank::Int128;
  if (contains(n, "long long")) return IntRank::LongLong;
  if (contains(n, "long")) return IntRank::Long;
  if (contains(n, "short")) return IntRank::Short;
  if (contains(n, "int") || n == "signed" || n == "unsigned") return IntRank::Int;
  return IntRank::Fixed;
}

types::FloatKind float_kind(std::string_view n, std::uint64_t size) {
  using types::FloatKind;
  if (contains(n, "128") && !contains(n, "long double")) return FloatKind::Float128;
  if (contains(n, "long double")) return FloatKind::LongDouble;
  switch (size) {
    case 2: return FloatKind::Half;
    case 4: return FloatKind::Float;
    case 8: return FloatKind::Double;
    default: return FloatKind::LongDouble;
  }
}

types::CallConv call_conv(std::uint64_t cc) {
  using types::CallConv;
  switch (cc) {
    case 0x01: return CallConv::Default;   // DW_CC_normal
    case 0xb1: return CallConv::Stdcall;   // DW_CC_BORLAND_stdcall
    case 0xb2: return CallConv::Pascal;    // DW_CC_BORLAND_pascal
    case 0xb3: return CallConv::Fastcall;  // DW_CC_BORLAND_msfastcall
    case 0xb5: return CallConv::Thiscall;  // DW_CC_BORLAND_thiscall
    case 0xb6: return CallConv::Fastcall;  // DW_CC_BORLAND_fastcall
    case 0xc0: return CallConv::Vectorcall;
    case 0xc1: return CallConv::Ms64;
    case 0xc2: return CallConv::SysV;
    case 0xcb: return CallConv::Regcall;
    default: return CallConv::Default;  // nocall, pass_by_*: not a convention
  }
}

std::uint32_t clamp32(std::uint64_t v) {
  return std::uint32_t(std::min<std::uint64_t>(v, std::numeric_limits<std::uint32_t>::max()));
}

class Importer {
 public:
  Importer(const Dwarf &dw, types::TypeStore &store, const ImportOptions &opt, DebugInfo &out)
      : dw_(dw), store_(store), opt_(opt), out_(out) {}

  void run() {
    for (const Unit &u : dw_.units()) {
      if (u.die_count == 0) continue;
      CompileUnit cu;
      cu.offset = u.offset;
      cu.version = u.version;
      cu.language = u.language;
      cu.name = std::string(dw_.string(u.first_die, dw::AT_name).value_or(""));
      cu.producer = std::string(dw_.string(u.first_die, dw::AT_producer).value_or(""));
      out_.units.push_back(std::move(cu));
    }
    if (opt_.resolve_declarations) index_definitions();

    const auto &dies = dw_.dies();
    for (std::uint32_t i = 0; i < dies.size(); ++i)
      if (is_type_tag(dies[i].tag)) node(i);
    drain();
    for (std::uint32_t i = 0; i < dies.size(); ++i) {
      if (dies[i].tag == dw::TAG_subprogram) function(i);
      else if (dies[i].tag == dw::TAG_variable) variable(i);
    }
    drain();
    detect_packing();
    if (std::size_t n = g_.break_invalid_cycles())
      out_.diagnostics.push_back({0, "broke " + std::to_string(n) + " invalid type cycles"});

    std::vector<TypeId> ids = store_.intern(g_);
    auto map = [&](TypeId t) { return t.is_local() ? ids[t.index()] : t; };
    for (Pending &p : funcs_) {
      p.fn.prototype = map(p.fn.prototype);
      for (LocalVariable &v : p.fn.locals) v.type = map(v.type);
      out_.functions.push_back(std::move(p.fn));
    }
    for (Variable &v : vars_) {
      v.type = map(v.type);
      out_.variables.push_back(std::move(v));
    }
    std::vector<std::pair<std::uint32_t, TypeId>> bases;
    for (const auto &[die, id] : memo_)
      if (dw_.die(die).tag == dw::TAG_base_type) bases.emplace_back(die, map(id));
    std::sort(bases.begin(), bases.end());
    for (const auto &[die, id] : bases) out_.base_type_names.emplace(id, std::string(name(die)));
    std::vector<std::pair<std::uint32_t, TypeId>> named;
    for (const auto &[die, id] : memo_) {
      const std::uint16_t tag = dw_.die(die).tag;
      if ((is_aggregate_tag(tag) || tag == dw::TAG_enumeration_type || tag == dw::TAG_typedef) && !name(die).empty())
        named.emplace_back(die, map(id));
    }
    std::sort(named.begin(), named.end());
    for (const auto &[die, id] : named)
      if (std::string_view file = dw_.decl_file(die); !file.empty()) out_.type_files.emplace(id, std::string(file));
    out_.types = ids;
    std::sort(out_.types.begin(), out_.types.end());
    out_.types.erase(std::unique(out_.types.begin(), out_.types.end()), out_.types.end());
    std::sort(out_.functions.begin(), out_.functions.end(), [](const Function &a, const Function &b) {
      return std::tie(a.entry, a.die_offset) < std::tie(b.entry, b.die_offset);
    });
    std::sort(out_.variables.begin(), out_.variables.end(), [](const Variable &a, const Variable &b) {
      return std::tie(a.address, a.die_offset) < std::tie(b.address, b.die_offset);
    });
  }

 private:
  struct Pending {
    Function fn;
  };

  std::string_view name(std::uint32_t die) const {
    return dw_.string(die, dw::AT_name).value_or(std::string_view{});
  }

  // A DIE's name; for a declaration that only points at a type unit
  // (clang's DW_AT_signature stubs), the name of the type it points at.
  std::string_view scope_name(std::uint32_t die) const {
    std::string_view n = name(die);
    if (n.empty())
      if (std::uint32_t sig = dw_.ref(die, dw::AT_signature); sig != kNoDie) n = name(sig);
    return n;
  }

  // Name with enclosing C++ namespaces and classes. An out-of-line
  // definition (DW_AT_specification) is scoped where its declaration is.
  std::string qualified(std::uint32_t die, std::string_view base) const {
    if (base.empty() || !dw_.unit_of(die).is_cxx()) return std::string(base);
    for (int k = 0; k < kMaxChain; ++k) {
      std::uint32_t spec = dw_.ref(die, dw::AT_specification);
      if (spec == kNoDie || spec == die) break;
      die = spec;
    }
    std::string out(base);
    std::uint32_t p = dw_.die(die).parent;
    for (int depth = 0; p != kNoDie && depth < kMaxChain; ++depth, p = dw_.die(p).parent) {
      std::uint16_t tag = dw_.die(p).tag;
      if (tag == dw::TAG_namespace) {
        std::string_view n = name(p);
        out = std::string(n.empty() ? "(anonymous namespace)" : n) + "::" + out;
      } else if (is_aggregate_tag(tag) || tag == dw::TAG_enumeration_type) {
        std::string_view n = scope_name(p);
        if (!n.empty()) out = std::string(n) + "::" + out;
      } else {
        break;
      }
    }
    return out;
  }

  // DIE, then what it completes or instantiates (specification,
  // abstract_origin), without repeats.
  std::vector<std::uint32_t> chain(std::uint32_t die) const {
    std::vector<std::uint32_t> out{die};
    for (int k = 0; k < kMaxChain; ++k) {
      std::uint32_t next = dw_.ref(out.back(), dw::AT_specification);
      if (next == kNoDie) next = dw_.ref(out.back(), dw::AT_abstract_origin);
      if (next == kNoDie || std::find(out.begin(), out.end(), next) != out.end()) break;
      out.push_back(next);
    }
    return out;
  }

  std::uint32_t first_with(const std::vector<std::uint32_t> &c, std::uint16_t at) const {
    for (std::uint32_t d : c)
      if (dw_.has(d, at)) return d;
    return kNoDie;
  }

  std::uint64_t byte_size(std::uint32_t die, std::uint64_t dflt) const {
    if (auto s = dw_.unsigned_value(die, dw::AT_byte_size)) return *s;
    if (auto b = dw_.unsigned_value(die, dw::AT_bit_size)) return (*b + 7) / 8;
    return dflt;
  }

  // Byte size of the type a DIE's DW_AT_type names, following typedefs and
  // qualifiers; for old-style bitfield offsets.
  std::uint64_t referenced_size(std::uint32_t die) const {
    std::uint32_t t = dw_.ref(die, dw::AT_type);
    for (int k = 0; k < kMaxChain && t != kNoDie; ++k) {
      if (auto s = dw_.unsigned_value(t, dw::AT_byte_size)) return *s;
      if (dw_.die(t).tag == dw::TAG_pointer_type) return dw_.unit_of(t).addr_size;
      t = dw_.ref(t, dw::AT_type);
    }
    return 0;
  }

  std::string def_key(std::uint32_t die) const {
    std::uint16_t tag = dw_.die(die).tag;
    char kind = tag == dw::TAG_union_type ? 'u' : tag == dw::TAG_enumeration_type ? 'e' : 's';
    std::string q = qualified(die, name(die));
    return q.empty() ? std::string() : kind + q;
  }

  // A shallow signature: definitions that differ in it are different types.
  std::string def_signature(std::uint32_t die) const {
    std::string sig = std::to_string(byte_size(die, 0));
    for (std::uint32_t c = dw_.die(die).first_child; c != kNoDie; c = dw_.die(c).next_sibling) {
      sig += ',';
      sig += name(c);
    }
    return sig;
  }

  void index_definitions() {
    std::unordered_map<std::string, std::string> sigs;
    const auto &dies = dw_.dies();
    for (std::uint32_t i = 0; i < dies.size(); ++i) {
      std::uint16_t tag = dies[i].tag;
      if (!is_aggregate_tag(tag) && tag != dw::TAG_enumeration_type) continue;
      if (dw_.flag(i, dw::AT_declaration)) continue;
      std::string key = def_key(i);
      if (key.empty()) continue;
      std::string sig = def_signature(i);
      auto [it, fresh] = definition_.try_emplace(key, i);
      if (fresh) sigs.emplace(key, std::move(sig));
      else if (it->second != kNoDie && sigs[key] != sig) it->second = kNoDie;  // ambiguous
    }
  }

  std::uint32_t resolve_declaration(std::uint32_t die) const {
    if (!dw_.flag(die, dw::AT_declaration)) return die;
    // A stub for a type that lives in a type unit.
    if (std::uint32_t sig = dw_.ref(die, dw::AT_signature); sig != kNoDie) return sig;
    if (definition_.empty()) return die;
    std::uint16_t tag = dw_.die(die).tag;
    if (!is_aggregate_tag(tag) && tag != dw::TAG_enumeration_type) return die;
    auto it = definition_.find(def_key(die));
    return it == definition_.end() || it->second == kNoDie ? die : it->second;
  }

  TypeId node(std::uint32_t die) {
    die = resolve_declaration(die);
    if (auto it = memo_.find(die); it != memo_.end()) return it->second;
    TypeId id = g_.reserve();
    memo_.emplace(die, id);
    work_.push_back(die);
    return id;
  }

  // The type a DIE's DW_AT_type refers to; void if it has none.
  TypeId type_of(std::uint32_t die) {
    if (!dw_.has(die, dw::AT_type)) return store_.void_type();
    std::uint32_t t = dw_.ref(die, dw::AT_type);
    if (t == kNoDie) return store_.undefined(1);  // e.g. a reference into a supplementary file
    return node(t);
  }

  void drain() {
    while (!work_.empty()) {
      std::uint32_t d = work_.back();
      work_.pop_back();
      g_.set(memo_.at(d), build(d));
    }
  }

  types::Type build(std::uint32_t d) {
    using namespace types;
    const Unit &u = dw_.unit_of(d);
    switch (dw_.die(d).tag) {
      case dw::TAG_base_type: return base_type(d);
      case dw::TAG_unspecified_type: return VoidType{};
      case dw::TAG_pointer_type:
        return PointerType{type_of(d), clamp32(byte_size(d, u.addr_size)), PointerKind::Pointer};
      case dw::TAG_reference_type:
        return PointerType{type_of(d), clamp32(byte_size(d, u.addr_size)), PointerKind::LValueRef};
      case dw::TAG_rvalue_reference_type:
        return PointerType{type_of(d), clamp32(byte_size(d, u.addr_size)), PointerKind::RValueRef};
      case dw::TAG_const_type:
      case dw::TAG_immutable_type:
      case dw::TAG_volatile_type:
      case dw::TAG_restrict_type:
      case dw::TAG_atomic_type: return qualifiers(d);
      case dw::TAG_typedef: {
        std::string n = qualified(d, name(d));
        if (n.empty()) return QualifiedType{type_of(d), 0};
        return TypedefType{std::move(n), type_of(d)};
      }
      case dw::TAG_structure_type:
      case dw::TAG_class_type:
      case dw::TAG_union_type: return aggregate(d);
      case dw::TAG_enumeration_type: return enumeration(d);
      case dw::TAG_array_type: return array(d);
      case dw::TAG_subroutine_type: return subroutine(d, d);
      case dw::TAG_ptr_to_member_type:
      default: return UndefinedType{clamp32(std::max<std::uint64_t>(byte_size(d, 1), 1))};
    }
  }

  static std::uint8_t qualifier_bit(std::uint16_t tag) {
    switch (tag) {
      case dw::TAG_const_type:
      case dw::TAG_immutable_type: return types::kConst;
      case dw::TAG_volatile_type: return types::kVolatile;
      case dw::TAG_restrict_type: return types::kRestrict;
      case dw::TAG_atomic_type: return types::kAtomic;
      default: return 0;
    }
  }

  // A run of qualifier DIEs (const -> volatile -> T) becomes one node with
  // all their bits, so `const volatile T` is one type whatever order the
  // compiler nested them in (and matches CodeView's single LF_MODIFIER).
  types::Type qualifiers(std::uint32_t d) {
    std::uint8_t bits = 0;
    for (int k = 0; k < kMaxChain; ++k) {
      bits |= qualifier_bit(dw_.die(d).tag);
      if (!dw_.has(d, dw::AT_type)) return types::QualifiedType{store_.void_type(), bits};
      std::uint32_t t = dw_.ref(d, dw::AT_type);
      if (t == kNoDie) return types::QualifiedType{store_.undefined(1), bits};
      if (!qualifier_bit(dw_.die(t).tag) || k + 1 == kMaxChain) return types::QualifiedType{node(t), bits};
      d = t;
    }
    return types::QualifiedType{store_.undefined(1), bits};
  }

  types::Type base_type(std::uint32_t d) {
    using namespace types;
    std::string_view n = name(d);
    std::uint64_t size = byte_size(d, 0);
    std::uint64_t enc = dw_.unsigned_value(d, dw::AT_encoding).value_or(0);
    switch (enc) {
      case dw::ATE_boolean: return BoolType{clamp32(size)};
      case dw::ATE_float: return FloatType{clamp32(size), float_kind(n, size), false};
      case dw::ATE_complex_float: return FloatType{clamp32(size), float_kind(n, size / 2), true};
      case dw::ATE_signed:
      case dw::ATE_signed_char: return IntType{clamp32(size), true, rank_from_name(n)};
      case dw::ATE_unsigned:
      case dw::ATE_unsigned_char:
      case dw::ATE_UTF: {
        IntRank r = rank_from_name(n);
        // char is unsigned on AArch64 and RISC-V, signed elsewhere.
        return IntType{clamp32(size), false, r};
      }
      case dw::ATE_address: return IntType{clamp32(size), false, IntRank::Fixed};
      default: return UndefinedType{clamp32(std::max<std::uint64_t>(size, 1))};
    }
  }

  types::Type aggregate(std::uint32_t d) {
    using namespace types;
    AggregateType a;
    std::uint16_t tag = dw_.die(d).tag;
    a.kind = tag == dw::TAG_union_type ? AggregateKind::Union
             : tag == dw::TAG_class_type ? AggregateKind::Class
                                         : AggregateKind::Struct;
    a.name = qualified(d, name(d));
    a.size = byte_size(d, 0);
    a.alignment = clamp32(dw_.unsigned_value(d, dw::AT_alignment).value_or(0));
    a.complete = !dw_.flag(d, dw::AT_declaration);
    const bool big = dw_.big_endian();
    for (std::uint32_t c = dw_.die(d).first_child; c != kNoDie; c = dw_.die(c).next_sibling) {
      std::uint16_t ct = dw_.die(c).tag;
      if (ct != dw::TAG_member && ct != dw::TAG_inheritance) continue;
      if (dw_.flag(c, dw::AT_declaration) || dw_.flag(c, dw::AT_external)) continue;  // static
      Field f;
      f.name = std::string(name(c));
      f.type = type_of(c);
      std::uint64_t byte_off = 0;
      if (const AttrValue *loc = dw_.find(c, dw::AT_data_member_location)) {
        if (auto v = dw_.unsigned_value(c, dw::AT_data_member_location)) byte_off = *v;
        else byte_off = member_location_expr(loc->bytes);
      }
      f.bit_size = clamp32(dw_.unsigned_value(c, dw::AT_bit_size).value_or(0));
      if (auto dbo = dw_.unsigned_value(c, dw::AT_data_bit_offset)) {
        f.bit_offset = *dbo;
      } else if (auto bo = dw_.unsigned_value(c, dw::AT_bit_offset); bo && f.bit_size) {
        // DWARF 2-4: bit_offset counts from the storage unit's most
        // significant bit.
        std::uint64_t storage = byte_size(c, referenced_size(c)) * 8;
        f.bit_offset = big ? byte_off * 8 + *bo : byte_off * 8 + storage - *bo - f.bit_size;
      } else {
        f.bit_offset = byte_off * 8;
      }
      a.fields.push_back(std::move(f));
    }
    return a;
  }

  static std::uint64_t member_location_expr(std::string_view expr) {
    // DWARF 2 style: DW_OP_plus_uconst n (or DW_OP_constu n).
    if (expr.size() < 2) return 0;
    auto op = std::uint8_t(expr[0]);
    if (op != dw::OP_plus_uconst && op != dw::OP_constu) return 0;
    std::uint64_t v = 0;
    unsigned shift = 0;
    for (std::size_t i = 1; i < expr.size() && shift < 64; ++i, shift += 7) {
      auto b = std::uint8_t(expr[i]);
      v |= std::uint64_t(b & 0x7f) << shift;
      if (!(b & 0x80)) break;
    }
    return v;
  }

  types::Type enumeration(std::uint32_t d) {
    using namespace types;
    EnumType e;
    e.name = qualified(d, name(d));
    e.complete = !dw_.flag(d, dw::AT_declaration);
    std::uint64_t size = byte_size(d, 0);
    std::optional<bool> is_signed;
    std::uint32_t under = dw_.ref(d, dw::AT_type);
    for (int k = 0; k < kMaxChain && under != kNoDie; ++k) {
      if (dw_.die(under).tag == dw::TAG_base_type) {
        auto enc = dw_.unsigned_value(under, dw::AT_encoding).value_or(0);
        is_signed = enc == dw::ATE_signed || enc == dw::ATE_signed_char;
        if (!size) size = byte_size(under, 0);
        break;
      }
      under = dw_.ref(under, dw::AT_type);
    }
    std::vector<std::uint32_t> kids;
    for (std::uint32_t c = dw_.die(d).first_child; c != kNoDie; c = dw_.die(c).next_sibling)
      if (dw_.die(c).tag == dw::TAG_enumerator) kids.push_back(c);
    if (!is_signed) {
      // No underlying type: signed if any value was written as negative.
      is_signed = false;
      for (std::uint32_t c : kids) {
        const AttrValue *v = dw_.find(c, dw::AT_const_value);
        if (v && v->form == 0x0d /* sdata */ && std::int64_t(v->u) < 0) is_signed = true;
      }
    }
    e.is_signed = *is_signed;
    e.size = clamp32(size ? size : 4);
    for (std::uint32_t c : kids) {
      std::int64_t value = 0;
      if (e.is_signed) value = dw_.signed_value(c, dw::AT_const_value).value_or(0);
      else value = std::int64_t(dw_.unsigned_value(c, dw::AT_const_value).value_or(0));
      e.values.push_back({std::string(name(c)), value});
    }
    return e;
  }

  std::uint64_t subrange_count(std::uint32_t s) const {
    if (auto n = dw_.unsigned_value(s, dw::AT_count)) return *n;
    const AttrValue *ub = dw_.find(s, dw::AT_upper_bound);
    if (!ub) return 0;
    std::int64_t upper;
    switch (ub->form) {
      case dw::FORM_data1:
      case dw::FORM_data2:
      case dw::FORM_data4:
      case dw::FORM_data8: {
        unsigned bytes = ub->form == dw::FORM_data1   ? 1
                         : ub->form == dw::FORM_data2 ? 2
                         : ub->form == dw::FORM_data4 ? 4
                                                      : 8;
        std::uint64_t ones = bytes == 8 ? ~std::uint64_t(0) : (std::uint64_t(1) << (8 * bytes)) - 1;
        if (ub->u == ones) return 0;  // -1: unknown bound
        upper = std::int64_t(std::min<std::uint64_t>(ub->u, std::uint64_t(1) << 62));
        break;
      }
      case dw::FORM_sdata:
      case dw::FORM_udata:
      case dw::FORM_implicit_const: upper = std::int64_t(ub->u); break;
      default: return 0;  // variable length
    }
    std::int64_t lower = dw_.signed_value(s, dw::AT_lower_bound).value_or(0);
    if (upper < lower || upper - lower >= (std::int64_t(1) << 62)) return 0;
    return std::uint64_t(upper - lower) + 1;
  }

  types::Type array(std::uint32_t d) {
    using namespace types;
    TypeId elem = type_of(d);
    std::vector<std::uint64_t> counts;
    for (std::uint32_t c = dw_.die(d).first_child; c != kNoDie; c = dw_.die(c).next_sibling)
      if (dw_.die(c).tag == dw::TAG_subrange_type || dw_.die(c).tag == dw::TAG_enumeration_type)
        counts.push_back(dw_.die(c).tag == dw::TAG_subrange_type ? subrange_count(c) : 0);
    if (counts.empty()) return ArrayType{elem, 0};
    for (std::size_t i = counts.size() - 1; i > 0; --i) elem = g_.add(ArrayType{elem, counts[i]});
    return ArrayType{elem, counts[0]};
  }

  // A function type from a subroutine type or subprogram DIE (`params`
  // names the DIE whose children are the parameters).
  types::FunctionType subroutine(std::uint32_t ret_die, std::uint32_t params,
                                 std::vector<std::string> *names = nullptr) {
    using namespace types;
    FunctionType f;
    f.ret = type_of(ret_die);
    f.cc = call_conv(dw_.unsigned_value(ret_die, dw::AT_calling_convention).value_or(1));
    for (std::uint32_t c = dw_.die(params).first_child; c != kNoDie; c = dw_.die(c).next_sibling) {
      std::uint16_t tag = dw_.die(c).tag;
      if (tag == dw::TAG_unspecified_parameters) f.varargs = true;
      if (tag != dw::TAG_formal_parameter) continue;
      std::vector<std::uint32_t> pc = chain(c);
      std::uint32_t named = first_with(pc, dw::AT_name);
      std::uint32_t typed = first_with(pc, dw::AT_type);
      std::string n = named == kNoDie ? std::string() : std::string(name(named));
      if (names) names->push_back(n);
      f.params.push_back({std::move(n), typed == kNoDie ? store_.undefined(1) : type_of(typed)});
    }
    return f;
  }

  static std::size_t param_count(const Dwarf &dw, std::uint32_t die) {
    std::size_t n = 0;
    for (std::uint32_t c = dw.die(die).first_child; c != kNoDie; c = dw.die(c).next_sibling)
      n += dw.die(c).tag == dw::TAG_formal_parameter || dw.die(c).tag == dw::TAG_unspecified_parameters;
    return n;
  }

  bool params_are_references(std::uint32_t die) const {
    for (std::uint32_t c = dw_.die(die).first_child; c != kNoDie; c = dw_.die(c).next_sibling)
      if (dw_.die(c).tag == dw::TAG_formal_parameter && dw_.has(c, dw::AT_abstract_origin))
        return true;
    return false;
  }

  std::vector<std::string> formal_names(std::uint32_t die) const {
    std::vector<std::string> out;
    for (std::uint32_t c = dw_.die(die).first_child; c != kNoDie; c = dw_.die(c).next_sibling)
      if (dw_.die(c).tag == dw::TAG_formal_parameter) out.emplace_back(name(c));
    return out;
  }

  void function(std::uint32_t d) {
    if (dw_.flag(d, dw::AT_declaration)) return;
    std::vector<AddressRange> ranges = dw_.ranges(d);
    if (ranges.empty()) return;
    std::vector<std::uint32_t> c = chain(d);

    Function fn;
    fn.die_offset = dw_.die(d).offset;
    if (std::uint32_t n = first_with(c, dw::AT_name); n != kNoDie) {
      fn.name = std::string(name(n));
      fn.qualified_name = qualified(c.back(), fn.name);
    }
    for (std::uint16_t at : {dw::AT_linkage_name, dw::AT_MIPS_linkage_name})
      if (std::uint32_t n = first_with(c, at); n != kNoDie) {
        fn.linkage_name = std::string(dw_.string(n, at).value_or(""));
        break;
      }
    for (std::uint32_t x : c) {
      fn.external |= dw_.flag(x, dw::AT_external);
      fn.noreturn |= dw_.flag(x, dw::AT_noreturn);
    }

    // Parameters come from the first DIE in the chain that declares them
    // itself. Concrete instances of inlined functions only point at their
    // abstract origin's parameters, in no reliable order and sometimes
    // repeated (GCC emits an extra entry for a constant-propagated copy).
    std::uint32_t params = kNoDie;
    for (std::uint32_t x : c)
      if (param_count(dw_, x) && !params_are_references(x)) {
        params = x;
        break;
      }
    if (params == kNoDie) {
      params = d;
      for (std::uint32_t x : c)
        if (param_count(dw_, x) > param_count(dw_, params)) params = x;
    }
    std::uint32_t ret = first_with(c, dw::AT_type);
    std::uint32_t cc = first_with(c, dw::AT_calling_convention);
    types::FunctionType ft = subroutine(ret == kNoDie ? d : ret, params, &fn.param_names);
    // A C++ declaration's parameters are unnamed; the definition names them.
    for (std::uint32_t x : c) {
      if (x == params || params_are_references(x)) continue;
      std::vector<std::string> names = formal_names(x);
      if (names.size() != ft.params.size()) continue;
      for (std::size_t i = 0; i < names.size(); ++i)
        if (ft.params[i].name.empty() && !names[i].empty())
          ft.params[i].name = fn.param_names[i] = names[i];
    }
    if (cc != kNoDie) {
      std::uint64_t v = dw_.unsigned_value(cc, dw::AT_calling_convention).value_or(1);
      ft.cc = call_conv(v);
      fn.abi_changed = v == 0x03;  // DW_CC_nocall
    } else {
      ft.cc = types::CallConv::Default;
    }
    fn.prototype = g_.add(std::move(ft));
    fn.frame_base = location(d, dw::AT_frame_base);
    // Parameters with their locations are the concrete DIE's own (named
    // through their abstract origin), else the declaring DIE's.
    collect_locals(param_count(dw_, d) ? d : params, d, fn.locals, 0);

    // Entry: DW_AT_entry_pc, else low_pc, else the first range as listed.
    fn.entry = ranges.front().begin;
    if (auto lo = dw_.address(d, dw::AT_low_pc)) fn.entry = *lo;
    if (auto e = dw_.address(d, dw::AT_entry_pc)) fn.entry = *e;
    else if (auto off = dw_.unsigned_value(d, dw::AT_entry_pc); off && dw_.unit_of(d).version >= 5)
      fn.entry = dw_.address(d, dw::AT_low_pc).value_or(ranges.front().begin) + *off;
    std::sort(ranges.begin(), ranges.end());
    fn.ranges = std::move(ranges);
    funcs_.push_back({std::move(fn)});
  }

  // A location that is one simple operation (fbreg, breg, reg, CFA); a
  // location list or anything longer is Unknown.
  LocalVariable location(std::uint32_t die, std::uint16_t at) const {
    LocalVariable out;
    const AttrValue *v = dw_.find(die, at);
    if (v == nullptr || v->bytes.empty()) return out;
    switch (v->form) {
      case dw::FORM_exprloc:
      case dw::FORM_block:
      case dw::FORM_block1:
      case dw::FORM_block2:
      case dw::FORM_block4: break;
      default: return out;
    }
    std::span<const std::uint8_t> expr(reinterpret_cast<const std::uint8_t *>(v->bytes.data()), v->bytes.size());
    try {
      Cursor c(expr, dw_.big_endian());
      const std::uint8_t op = c.u8();
      using L = LocalVariable::Location;
      if (op == 0x91) {  // DW_OP_fbreg
        out.offset = static_cast<std::int32_t>(c.sleb());
        out.location = L::FrameRelative;
      } else if (op >= 0x70 && op <= 0x8f) {  // DW_OP_breg0..31
        out.reg = static_cast<std::uint16_t>(op - 0x70);
        out.offset = static_cast<std::int32_t>(c.sleb());
        out.location = L::RegisterRelative;
      } else if (op == 0x92) {  // DW_OP_bregx
        out.reg = static_cast<std::uint16_t>(c.uleb());
        out.offset = static_cast<std::int32_t>(c.sleb());
        out.location = L::RegisterRelative;
      } else if (op >= 0x50 && op <= 0x6f) {  // DW_OP_reg0..31
        out.reg = static_cast<std::uint16_t>(op - 0x50);
        out.location = L::Register;
      } else if (op == 0x90) {  // DW_OP_regx
        out.reg = static_cast<std::uint16_t>(c.uleb());
        out.location = L::Register;
      } else if (op == 0x9c) {  // DW_OP_call_frame_cfa
        out.location = L::Cfa;
      }
      if (!c.at_end()) out.location = L::Unknown;
    } catch (const FormatError &) {
      out.location = LocalVariable::Location::Unknown;
    }
    return out;
  }

  // Formal parameters (of `params`, the DIE that declares them) and the
  // variables of `scope` and its lexical blocks, in DIE order.
  void collect_locals(std::uint32_t params, std::uint32_t scope, std::vector<LocalVariable> &out, int depth) {
    if (depth > kMaxChain) return;
    if (depth == 0 && params != scope)
      for (std::uint32_t c = dw_.die(params).first_child; c != kNoDie; c = dw_.die(c).next_sibling)
        if (dw_.die(c).tag == dw::TAG_formal_parameter) out.push_back(local(c, true, 0));
    for (std::uint32_t c = dw_.die(scope).first_child; c != kNoDie; c = dw_.die(c).next_sibling) {
      const std::uint16_t t = dw_.die(c).tag;
      if (t == dw::TAG_formal_parameter && depth == 0 && params == scope) out.push_back(local(c, true, 0));
      else if (t == dw::TAG_variable && !dw_.static_address(c)) out.push_back(local(c, false, scope == params ? 0 : block_start(scope)));
      else if (t == dw::TAG_lexical_block) collect_locals(params, c, out, depth + 1);
    }
  }
  std::uint64_t block_start(std::uint32_t die) const {
    if (auto lo = dw_.address(die, dw::AT_low_pc)) return *lo;
    std::vector<AddressRange> r = dw_.ranges(die);
    return r.empty() ? 0 : r.front().begin;
  }
  LocalVariable local(std::uint32_t c, bool param, std::uint64_t scope) {
    std::vector<std::uint32_t> ch = chain(c);
    LocalVariable v = location(c, dw::AT_location);
    if (std::uint32_t n = first_with(ch, dw::AT_name); n != kNoDie) v.name = std::string(name(n));
    std::uint32_t typed = first_with(ch, dw::AT_type);
    v.type = typed == kNoDie ? store_.undefined(1) : type_of(typed);
    v.is_param = param;
    v.scope_start = scope;
    return v;
  }

  void variable(std::uint32_t d) {
    auto addr = dw_.static_address(d);
    if (!addr) return;
    std::vector<std::uint32_t> c = chain(d);
    Variable v;
    v.die_offset = dw_.die(d).offset;
    v.address = *addr;
    if (std::uint32_t n = first_with(c, dw::AT_name); n != kNoDie) {
      v.name = std::string(name(n));
      v.qualified_name = qualified(c.back(), v.name);
    }
    for (std::uint16_t at : {dw::AT_linkage_name, dw::AT_MIPS_linkage_name})
      if (std::uint32_t n = first_with(c, at); n != kNoDie) {
        v.linkage_name = std::string(dw_.string(n, at).value_or(""));
        break;
      }
    for (std::uint32_t x : c) v.external |= dw_.flag(x, dw::AT_external);
    std::uint32_t typed = first_with(c, dw::AT_type);
    v.type = typed == kNoDie ? store_.undefined(1) : type_of(typed);
    std::uint32_t p = dw_.die(d).parent;
    for (int k = 0; k < 4 * kMaxChain && p != kNoDie; ++k, p = dw_.die(p).parent) {
      std::uint16_t t = dw_.die(p).tag;
      if (t == dw::TAG_subprogram || t == dw::TAG_lexical_block || t == dw::TAG_inlined_subroutine)
        v.function_local = true;
      if (t == dw::TAG_subprogram) {
        if (std::uint32_t n = first_with(chain(p), dw::AT_name); n != kNoDie) v.scope = std::string(name(n));
        break;
      }
    }
    vars_.push_back(std::move(v));
  }

  void detect_packing() {
    std::vector<std::pair<TypeId, std::uint32_t>> aggs;  // node, address size
    for (auto &[die, id] : memo_)
      if (g_.at(id).kind() == types::Kind::Aggregate) aggs.push_back({id, dw_.unit_of(die).addr_size});
    types::infer_packing(g_, store_, std::move(aggs));
  }

  const Dwarf &dw_;
  types::TypeStore &store_;
  const ImportOptions &opt_;
  DebugInfo &out_;
  types::TypeGraph g_;
  std::unordered_map<std::uint32_t, TypeId> memo_;
  std::vector<std::uint32_t> work_;
  std::unordered_map<std::string, std::uint32_t> definition_;
  std::vector<Pending> funcs_;
  std::vector<Variable> vars_;
};

}  // namespace

DebugInfo import_dwarf(const Sections &sections, types::TypeStore &store,
                       const ImportOptions &options) {
  DebugInfo out;
  Dwarf dw(sections, out.diagnostics);
  Importer(dw, store, options, out).run();
  return out;
}

}  // namespace revkit::debuginfo
