// CodeView type records into revkit types.
//
// The mapping is chosen so that a C type hashes the same whether it came
// from DWARF or from a PDB: simple types get the C rank DWARF base types
// get from their names, CodeView's "near C" calling convention is the
// default one, anonymous tags are unnamed, bitfield positions become
// absolute bit offsets, and packing is inferred by the rule DWARF uses.
// See docs/types.md for the exceptions.

#include "pdb_types.h"

#include "codeview.h"
#include "revkit/types/packing.h"

#include <algorithm>
#include <cstdio>
#include <limits>
#include <map>
#include <set>
#include <unordered_set>
#include <utility>

namespace revkit::debuginfo::pdb {
namespace {

using types::TypeId;

// Bounds on chains a malformed stream could make cyclic or long.
constexpr int kMaxDepth = 32;
constexpr std::size_t kMaxFieldLists = 4096;
constexpr std::size_t kMaxWarnings = 64;

std::uint32_t clamp32(std::uint64_t v) {
  return std::uint32_t(std::min<std::uint64_t>(v, std::numeric_limits<std::uint32_t>::max()));
}

bool is_aggregate_kind(std::uint16_t k) {
  return k == cv::LF_CLASS || k == cv::LF_STRUCTURE || k == cv::LF_INTERFACE || k == cv::LF_UNION ||
         k == cv::LF_CLASS2 || k == cv::LF_STRUCTURE2 || k == cv::LF_INTERFACE2;
}

// LF_CLASS2 and the like as the record kind they stand for.
std::uint16_t base_kind(std::uint16_t k) {
  switch (k) {
    case cv::LF_CLASS2: return cv::LF_CLASS;
    case cv::LF_STRUCTURE2: return cv::LF_STRUCTURE;
    case cv::LF_INTERFACE2: return cv::LF_INTERFACE;
    default: return k;
  }
}

// CodeView spells an unnamed tag "<unnamed-tag>", "<anonymous-tag>",
// "<unnamed-type-NAME>" or "__unnamed", possibly scoped ("f::<unnamed-tag>").
// DWARF leaves such types nameless, so do we.
std::string_view tag_name(std::string_view name) {
  if (name == "__unnamed") return {};
  for (std::string_view marker : {"<unnamed-", "<anonymous-"}) {
    std::size_t p = name.rfind(marker);
    if (p == std::string_view::npos) continue;
    if ((p == 0 || (p >= 2 && name.substr(p - 2, 2) == "::")) && name.ends_with(">") &&
        name.find("::", p) == std::string_view::npos)
      return {};
  }
  return name;
}

types::CallConv call_conv(std::uint8_t cc) {
  using types::CallConv;
  switch (cc) {
    case cv::kCallNearC:
    case cv::kCallFarC: return CallConv::Default;
    case cv::kCallNearPascal:
    case cv::kCallFarPascal: return CallConv::Pascal;
    case cv::kCallNearFast:
    case cv::kCallFarFast: return CallConv::Fastcall;
    case cv::kCallNearStd:
    case cv::kCallFarStd: return CallConv::Stdcall;
    case cv::kCallThis: return CallConv::Thiscall;
    case cv::kCallNearVector: return CallConv::Vectorcall;
    default: return CallConv::Other;
  }
}

// A simple type's kind byte as a revkit type, without the pointer mode.
types::Type simple_kind(std::uint32_t kind) {
  using namespace types;
  switch (kind) {
    case 0x03: return VoidType{};                               // T_VOID
    case 0x08: return IntType{4, true, IntRank::Long};          // T_HRESULT
    case 0x10: return IntType{1, true, IntRank::Char};          // T_CHAR (signed char)
    case 0x20: return IntType{1, false, IntRank::Char};         // T_UCHAR
    case 0x70: return IntType{1, true, IntRank::PlainChar};     // T_RCHAR (char)
    case 0x68: return IntType{1, true, IntRank::Char};          // T_INT1
    case 0x69: return IntType{1, false, IntRank::Char};         // T_UINT1
    case 0x71: return IntType{2, false, IntRank::WChar};        // T_WCHAR
    case 0x7a: return IntType{2, false, IntRank::Char16};       // T_CHAR16
    case 0x7b: return IntType{4, false, IntRank::Char32};       // T_CHAR32
    case 0x7c: return IntType{1, false, IntRank::Char8};        // T_CHAR8
    case 0x11: return IntType{2, true, IntRank::Short};         // T_SHORT
    case 0x21: return IntType{2, false, IntRank::Short};        // T_USHORT
    case 0x72: return IntType{2, true, IntRank::Short};         // T_INT2
    case 0x73: return IntType{2, false, IntRank::Short};        // T_UINT2
    case 0x12: return IntType{4, true, IntRank::Long};          // T_LONG
    case 0x22: return IntType{4, false, IntRank::Long};         // T_ULONG
    case 0x74: return IntType{4, true, IntRank::Int};           // T_INT4
    case 0x75: return IntType{4, false, IntRank::Int};          // T_UINT4
    case 0x13: return IntType{8, true, IntRank::LongLong};      // T_QUAD
    case 0x23: return IntType{8, false, IntRank::LongLong};     // T_UQUAD
    case 0x76: return IntType{8, true, IntRank::LongLong};      // T_INT8
    case 0x77: return IntType{8, false, IntRank::LongLong};     // T_UINT8
    case 0x14: return IntType{16, true, IntRank::Int128};       // T_OCT
    case 0x24: return IntType{16, false, IntRank::Int128};      // T_UOCT
    case 0x78: return IntType{16, true, IntRank::Int128};       // T_INT16
    case 0x79: return IntType{16, false, IntRank::Int128};      // T_UINT16
    case 0x30: return BoolType{1};                              // T_BOOL08
    case 0x31: return BoolType{2};
    case 0x32: return BoolType{4};
    case 0x33: return BoolType{8};
    case 0x34: return BoolType{16};
    case 0x46: return FloatType{2, FloatKind::Half, false};     // T_REAL16
    case 0x40: return FloatType{4, FloatKind::Float, false};    // T_REAL32
    case 0x45: return FloatType{4, FloatKind::Float, false};    // T_REAL32PP
    case 0x41: return FloatType{8, FloatKind::Double, false};   // T_REAL64
    case 0x42: return FloatType{10, FloatKind::LongDouble, false};  // T_REAL80
    // T_REAL128: clang writes it for any 16-byte float, which on x86-64
    // mingw is long double (x87 in 16 bytes); __float128 is rare.
    case 0x43: return FloatType{16, FloatKind::LongDouble, false};
    case 0x50: return FloatType{8, FloatKind::Float, true};     // T_CPLX32
    case 0x51: return FloatType{16, FloatKind::Double, true};   // T_CPLX64
    case 0x52: return FloatType{20, FloatKind::LongDouble, true};  // T_CPLX80
    case 0x53: return FloatType{32, FloatKind::LongDouble, true};  // T_CPLX128
    case 0x44: return UndefinedType{6};                         // T_REAL48
    default: return UndefinedType{1};  // T_NOTYPE, T_ABS, T_SEGMENT, unknown
  }
}

std::uint32_t simple_pointer_size(std::uint32_t mode) {
  switch (mode) {
    case 1: return 2;   // near (16-bit)
    case 2:
    case 3:
    case 4: return 4;   // far, huge, 32-bit near
    case 5: return 6;   // 16:32 far
    case 6: return 8;   // 64-bit
    case 7: return 16;  // 128-bit
    default: return 8;
  }
}

}  // namespace

Numeric read_numeric(Cursor &c) {
  std::uint16_t v = c.u16();
  if (v < cv::LF_NUMERIC) return {v, false, true};
  auto skip = [&](std::uint64_t n) {
    c.skip(n);
    return Numeric{0, false, false};
  };
  switch (v) {
    case cv::LF_CHAR: return {std::uint64_t(std::int64_t(std::int8_t(c.u8()))), true, true};
    case cv::LF_SHORT: return {std::uint64_t(std::int64_t(std::int16_t(c.u16()))), true, true};
    case cv::LF_USHORT: return {c.u16(), false, true};
    case cv::LF_LONG: return {std::uint64_t(std::int64_t(std::int32_t(c.u32()))), true, true};
    case cv::LF_ULONG: return {c.u32(), false, true};
    case cv::LF_QUADWORD: return {c.u64(), true, true};
    case cv::LF_UQUADWORD: return {c.u64(), false, true};
    case cv::LF_OCTWORD:
    case cv::LF_UOCTWORD: {
      std::uint64_t lo = c.u64();
      c.skip(8);
      return {lo, v == cv::LF_OCTWORD, true};
    }
    case cv::LF_REAL16: return skip(2);
    case cv::LF_REAL32: return skip(4);
    case cv::LF_REAL48: return skip(6);
    case cv::LF_REAL64:
    case cv::LF_COMPLEX32:
    case cv::LF_DATE: return skip(8);
    case cv::LF_REAL80: return skip(10);
    case cv::LF_REAL128:
    case cv::LF_COMPLEX64:
    case cv::LF_DECIMAL: return skip(16);
    case cv::LF_COMPLEX80: return skip(20);
    case cv::LF_COMPLEX128: return skip(32);
    case cv::LF_VARSTRING: return skip(c.u16());
    case cv::LF_UTF8STRING:
      read_name(c);
      return {0, false, false};
    default: throw FormatError("unknown numeric leaf " + std::to_string(v));
  }
}

std::string_view read_name(Cursor &c) {
  std::size_t start = c.pos();
  auto rest = c.bytes(c.remaining());
  std::size_t n = 0;
  while (n < rest.size() && rest[n] != 0) ++n;
  c.seek(start + std::min(n + 1, rest.size()));
  return {reinterpret_cast<const char *>(rest.data()), n};
}

TypeStream TypeStream::parse(std::vector<std::uint8_t> bytes, std::string *warning) {
  TypeStream s;
  s.bytes_ = std::move(bytes);
  Cursor c(s.bytes_, false);
  c.u32();  // version
  std::uint32_t header = c.u32();
  std::uint32_t begin = c.u32();
  std::uint32_t end = c.u32();
  std::uint32_t record_bytes = c.u32();
  if (header < 20 || header > s.bytes_.size()) throw FormatError("bad type stream header size");
  if (begin < cv::kFirstNonSimple || end < begin) throw FormatError("bad type index range");
  s.begin_ = begin;
  std::uint64_t limit = std::min<std::uint64_t>(std::uint64_t(header) + record_bytes, s.bytes_.size());
  if (std::uint64_t(header) + record_bytes > s.bytes_.size() && warning)
    *warning = "type records run past the end of the stream";
  std::uint64_t pos = header;
  std::uint64_t want = end - begin;
  s.entries_.reserve(std::size_t(std::min<std::uint64_t>(want, (limit - pos) / 4)));
  while (s.entries_.size() < want && pos + 4 <= limit) {
    std::uint16_t len = std::uint16_t(s.bytes_[pos] | s.bytes_[pos + 1] << 8);
    if (len < 2 || pos + 2 + len > limit) {
      if (warning) *warning = "bad type record length at offset " + std::to_string(pos);
      break;
    }
    std::uint16_t kind = std::uint16_t(s.bytes_[pos + 2] | s.bytes_[pos + 3] << 8);
    s.entries_.push_back({std::uint32_t(pos + 4), std::uint32_t(len - 2), kind});
    pos += 2 + std::uint64_t(len);
  }
  if (s.entries_.size() < want && warning && warning->empty())
    *warning = "type stream has " + std::to_string(s.entries_.size()) + " of " +
               std::to_string(want) + " records";
  return s;
}

TypeRecord TypeStream::record(std::uint32_t ti) const {
  if (!contains(ti)) return {};
  const Entry &e = entries_[ti - begin_];
  return {e.kind, std::span<const std::uint8_t>(bytes_).subspan(e.offset, e.size)};
}

TypeImporter::TypeImporter(const TypeStream &tpi, types::TypeStore &store, unsigned pointer_size,
                           bool resolve_forward_refs, std::vector<Diagnostic> &diagnostics)
    : tpi_(tpi), store_(store), pointer_size_(pointer_size),
      resolve_forward_refs_(resolve_forward_refs), diags_(diagnostics),
      budget_(4 * std::uint64_t{tpi.byte_size()} + (std::uint64_t{1} << 20)) {}

bool TypeImporter::charge(std::uint32_t ti) {
  if (budget_ == 0) return false;
  if (--budget_ == 0) warn(ti, "too many parameters, fields and enumerators in all; the rest are dropped");
  return budget_ != 0;
}

void TypeImporter::warn(std::uint32_t ti, const std::string &msg) {
  if (warnings_++ < kMaxWarnings) diags_.push_back({ti, "type 0x" + [&] {
    char buf[16];
    std::snprintf(buf, sizeof buf, "%x", ti);
    return std::string(buf);
  }() + ": " + msg});
}

TypeId TypeImporter::simple(std::uint32_t ti) {
  std::uint32_t mode = (ti >> cv::kSimpleModeShift) & cv::kSimpleModeMask;
  TypeId base = store_.intern(simple_kind(ti & cv::kSimpleKindMask));
  if (mode == 0) return base;
  return store_.pointer_to(base, simple_pointer_size(mode));
}

std::optional<TypeImporter::Aggregate> TypeImporter::aggregate_header(const TypeRecord &r) const {
  Aggregate a;
  a.kind = base_kind(r.kind);
  Cursor c(r.data, false);
  try {
    if (r.kind == cv::LF_CLASS2 || r.kind == cv::LF_STRUCTURE2 || r.kind == cv::LF_INTERFACE2) {
      // MSVC 17.x: 32-bit properties, the field list, derived list and
      // vshape, then the count and the size as numerics (Ghidra's
      // Class19MsType reads them the same way).
      a.props = static_cast<std::uint16_t>(c.u32());
      a.fields = c.u32();
      c.u32();  // derived
      c.u32();  // vshape
      a.count = static_cast<std::uint16_t>(read_numeric(c).bits);
      a.size = read_numeric(c).bits;
      a.name = read_name(c);
      if ((a.props & cv::kPropHasUniqueName) && !c.at_end()) a.unique_name = read_name(c);
      return a;
    }
    a.count = c.u16();
    a.props = c.u16();
    if (r.kind == cv::LF_ENUM) {
      a.underlying = c.u32();
      a.fields = c.u32();
    } else if (r.kind == cv::LF_UNION) {
      a.fields = c.u32();
      a.size = read_numeric(c).bits;
    } else {
      a.fields = c.u32();
      c.u32();  // derived
      c.u32();  // vshape
      a.size = read_numeric(c).bits;
    }
    a.name = read_name(c);
    if ((a.props & cv::kPropHasUniqueName) && !c.at_end()) a.unique_name = read_name(c);
  } catch (const FormatError &) {
    return std::nullopt;
  }
  return a;
}

std::string TypeImporter::definition_key(const Aggregate &a) const {
  char kind = a.kind == cv::LF_UNION ? 'u' : a.kind == cv::LF_ENUM ? 'e' : 's';
  std::string_view n = a.unique_name.empty() ? a.name : a.unique_name;
  if (tag_name(a.name).empty()) return {};
  return kind + std::string(n);
}

void TypeImporter::index_definitions() {
  indexed_ = true;
  for (std::uint32_t ti = tpi_.begin(); ti < tpi_.end(); ++ti) {
    TypeRecord r = tpi_.record(ti);
    if (!is_aggregate_kind(r.kind) && r.kind != cv::LF_ENUM) continue;
    auto a = aggregate_header(r);
    if (!a || (a->props & cv::kPropForwardRef)) continue;
    std::string key = definition_key(*a);
    if (key.empty()) continue;
    auto [it, fresh] = definitions_.try_emplace(std::move(key), ti);
    if (!fresh) it->second = 0;  // two different definitions: ambiguous
  }
}

std::uint32_t TypeImporter::resolve(std::uint32_t ti) {
  if (!resolve_forward_refs_) return ti;
  TypeRecord r = tpi_.record(ti);
  if (!is_aggregate_kind(r.kind) && r.kind != cv::LF_ENUM) return ti;
  auto a = aggregate_header(r);
  if (!a || !(a->props & cv::kPropForwardRef)) return ti;
  if (!indexed_) index_definitions();
  auto it = definitions_.find(definition_key(*a));
  return it == definitions_.end() || it->second == 0 ? ti : it->second;
}

std::string_view TypeImporter::tag(std::uint32_t ti) {
  if (ti < cv::kFirstNonSimple) return {};
  TypeRecord r = tpi_.record(resolve(ti));
  if (!is_aggregate_kind(r.kind) && r.kind != cv::LF_ENUM) return {};
  auto a = aggregate_header(r);
  return a ? tag_name(a->name) : std::string_view{};
}

TypeId TypeImporter::type(std::uint32_t ti) {
  if (ti < cv::kFirstNonSimple) return simple(ti);
  ti = resolve(ti);
  if (auto it = memo_.find(ti); it != memo_.end()) return it->second;
  TypeId id = g_.reserve();
  memo_.emplace(ti, id);
  work_.push_back(ti);
  return id;
}

void TypeImporter::drain() {
  while (!work_.empty()) {
    std::uint32_t ti = work_.back();
    work_.pop_back();
    types::Type t;
    try {
      t = build(ti);
    } catch (const FormatError &e) {
      warn(ti, e.what());
      t = types::UndefinedType{std::max<std::uint32_t>(1, clamp32(byte_size(ti)))};
    }
    g_.set(memo_.at(ti), std::move(t));
  }
}

std::uint64_t TypeImporter::byte_size(std::uint32_t ti, int depth) {
  if (depth > kMaxDepth) return 0;
  if (ti < cv::kFirstNonSimple) {
    std::uint32_t mode = (ti >> cv::kSimpleModeShift) & cv::kSimpleModeMask;
    if (mode) return simple_pointer_size(mode);
    types::Type t = simple_kind(ti & cv::kSimpleKindMask);
    if (auto *i = t.as<types::IntType>()) return i->size;
    if (auto *f = t.as<types::FloatType>()) return f->size;
    if (auto *b = t.as<types::BoolType>()) return b->size;
    if (auto *u = t.as<types::UndefinedType>()) return (ti & 0xff) == 0x44 ? u->size : 0;
    return 0;
  }
  ti = resolve(ti);
  TypeRecord r = tpi_.record(ti);
  try {
    Cursor c(r.data, false);
    switch (r.kind) {
      case cv::LF_MODIFIER: return byte_size(c.u32(), depth + 1);
      case cv::LF_BITFIELD: return byte_size(c.u32(), depth + 1);
      case cv::LF_POINTER: {
        c.u32();
        std::uint32_t attrs = c.u32();
        std::uint32_t size = (attrs >> cv::kPtrSizeShift) & cv::kPtrSizeMask;
        if (size) return size;
        return (attrs & 0x1f) == cv::kPtrType64 ? 8 : pointer_size_;
      }
      case cv::LF_ARRAY:
        c.u32();
        c.u32();
        return read_numeric(c).bits;
      case cv::LF_ENUM: {
        auto a = aggregate_header(r);
        return a ? byte_size(a->underlying, depth + 1) : 0;
      }
      case cv::LF_ALIAS: return byte_size(c.u32(), depth + 1);
      default:
        if (is_aggregate_kind(r.kind)) {
          auto a = aggregate_header(r);
          return a ? a->size : 0;
        }
        return 0;
    }
  } catch (const FormatError &) {
    return 0;
  }
}

bool TypeImporter::is_signed_integer(std::uint32_t ti, int depth) {
  if (depth > kMaxDepth) return false;
  if (ti < cv::kFirstNonSimple) {
    types::Type t = simple_kind(ti & cv::kSimpleKindMask);
    auto *i = t.as<types::IntType>();
    return ((ti >> cv::kSimpleModeShift) & cv::kSimpleModeMask) == 0 && i && i->is_signed;
  }
  TypeRecord r = tpi_.record(ti);
  if (r.kind != cv::LF_MODIFIER && r.kind != cv::LF_ALIAS) return false;
  Cursor c(r.data, false);
  try {
    return is_signed_integer(c.u32(), depth + 1);
  } catch (const FormatError &) {
    return false;
  }
}

types::Type TypeImporter::build_pointer(Cursor &c) {
  using namespace types;
  std::uint32_t target = c.u32();
  std::uint32_t attrs = c.u32();
  std::uint32_t mode = (attrs >> cv::kPtrModeShift) & cv::kPtrModeMask;
  std::uint32_t size = (attrs >> cv::kPtrSizeShift) & cv::kPtrSizeMask;
  if (!size) size = (attrs & 0x1f) == cv::kPtrType64 ? 8 : pointer_size_;
  if (mode == cv::kPtrModeDataMember || mode == cv::kPtrModeMemberFunction)
    return UndefinedType{size};  // pointers to members, as in the DWARF importer
  PointerKind kind = mode == cv::kPtrModeLValueRef   ? PointerKind::LValueRef
                     : mode == cv::kPtrModeRValueRef ? PointerKind::RValueRef
                                                     : PointerKind::Pointer;
  PointerType p{type(target), size, kind};
  std::uint8_t quals = 0;
  if (attrs & cv::kPtrConst) quals |= kConst;
  if (attrs & cv::kPtrVolatile) quals |= kVolatile;
  if (attrs & cv::kPtrRestrict) quals |= kRestrict;
  if (!quals) return p;
  return QualifiedType{g_.add(p), quals};
}

types::Type TypeImporter::build_aggregate(std::uint32_t ti, const Aggregate &a) {
  using namespace types;
  AggregateType agg;
  agg.kind = a.kind == cv::LF_UNION ? AggregateKind::Union
             : a.kind == cv::LF_STRUCTURE ? AggregateKind::Struct
                                          : AggregateKind::Class;
  agg.name = std::string(tag_name(a.name));
  agg.complete = !(a.props & cv::kPropForwardRef);
  agg.size = agg.complete ? a.size : 0;
  if (!agg.complete) return agg;

  // The virtual functions this class introduces, by vftable offset, for
  // the struct its vftable pointer points to (C++ classes: docs/pdb.md).
  std::map<std::uint64_t, std::pair<std::string, std::uint32_t>> virtuals;
  bool vfptr = false;
  auto method = [&](std::uint16_t attrs, std::uint32_t mt, std::uint32_t vbaseoff, std::string_view name) {
    const std::uint16_t mprop = (attrs >> 2) & 7;
    if (mprop == 4 || mprop == 6) virtuals.emplace(vbaseoff, std::make_pair(std::string(name), mt));
  };
  std::unordered_set<std::uint32_t> seen;
  std::uint32_t list = a.fields;
  while (list >= cv::kFirstNonSimple && seen.insert(list).second && seen.size() <= kMaxFieldLists) {
    TypeRecord r = tpi_.record(list);
    if (r.kind != cv::LF_FIELDLIST) {
      if (r.kind) warn(ti, "field list is not an LF_FIELDLIST");
      break;
    }
    list = 0;
    Cursor c(r.data, false);
    while (c.remaining() >= 2) {
      // Entries are padded to 4 bytes with LF_PAD0..LF_PAD15 (0xf0-0xff).
      std::uint8_t b = r.data[c.pos()];
      if (b >= 0xf0) {
        c.skip(std::min<std::size_t>(std::max(1, b & 0x0f), c.remaining()));
        continue;
      }
      if (!charge(ti)) break;
      std::uint16_t leaf = c.u16();
      switch (leaf) {
        case cv::LF_MEMBER: {
          c.u16();  // attributes
          std::uint32_t mt = c.u32();
          std::uint64_t offset = read_numeric(c).bits;
          Field f;
          f.name = std::string(read_name(c));
          TypeRecord mr = mt >= cv::kFirstNonSimple ? tpi_.record(mt) : TypeRecord{};
          if (mr.kind == cv::LF_BITFIELD) {
            Cursor bc(mr.data, false);
            std::uint32_t under = bc.u32();
            std::uint8_t length = bc.u8();
            std::uint8_t position = bc.u8();
            f.type = type(under);
            f.bit_size = length;
            f.bit_offset = offset * 8 + position;
          } else {
            f.type = type(mt);
            f.bit_offset = offset * 8;
          }
          agg.fields.push_back(std::move(f));
          break;
        }
        case cv::LF_BCLASS: {
          // A non-virtual base: an unnamed field, as DWARF's inheritance.
          c.u16();
          std::uint32_t bt = c.u32();
          std::uint64_t offset = read_numeric(c).bits;
          agg.fields.push_back({std::string(), type(bt), offset * 8, 0});
          break;
        }
        case cv::LF_VBCLASS:
        case cv::LF_IVBCLASS:
          c.u16();
          c.u32();
          c.u32();
          read_numeric(c);
          read_numeric(c);
          break;
        case cv::LF_STMEMBER:
          c.u16();
          c.u32();
          read_name(c);
          break;
        case cv::LF_METHOD: {
          const std::uint16_t count = c.u16();
          const std::uint32_t ml = c.u32();
          const std::string_view name = read_name(c);
          // The overloads: attributes, type, and the vtable offset of an
          // introducing virtual.
          TypeRecord mr = ml >= cv::kFirstNonSimple ? tpi_.record(ml) : TypeRecord{};
          if (mr.kind != cv::LF_METHODLIST) break;
          Cursor mc(mr.data, false);
          for (std::uint16_t k = 0; k < count && mc.remaining() >= 8; ++k) {
            const std::uint16_t attrs = mc.u16();
            mc.u16();
            const std::uint32_t mt = mc.u32();
            const std::uint16_t mprop = (attrs >> 2) & 7;
            std::uint32_t off = 0;
            if (mprop == 4 || mprop == 6) off = mc.u32();
            method(attrs, mt, off, name);
          }
          break;
        }
        case cv::LF_ONEMETHOD: {
          std::uint16_t attrs = c.u16();
          const std::uint32_t mt = c.u32();
          std::uint16_t mprop = (attrs >> 2) & 7;
          std::uint32_t off = 0;
          if (mprop == 4 || mprop == 6) off = c.u32();  // introducing virtual: vtable offset
          method(attrs, mt, off, read_name(c));
          break;
        }
        case cv::LF_NESTTYPE:
          c.u16();
          c.u32();
          read_name(c);
          break;
        case cv::LF_VFUNCTAB:
          c.u16();
          c.u32();
          vfptr = true;
          break;
        case cv::LF_INDEX:
          c.u16();
          list = c.u32();
          break;
        default:
          warn(ti, "unknown field list entry " + std::to_string(leaf));
          c.seek(c.size());
          break;
      }
    }
  }
  // The class's own vftable pointer (LF_VFUNCTAB: MSVC puts it first) as a
  // field "vftable", pointing to a struct "<class>_vtbl" of the virtual
  // functions it introduces, at their slots; slots a base introduced are
  // gaps.
  if (vfptr && std::none_of(agg.fields.begin(), agg.fields.end(), [](const Field &f) { return f.bit_offset == 0; })) {
    AggregateType vt;
    vt.kind = AggregateKind::Struct;
    vt.name = agg.name.empty() ? std::string() : agg.name + "_vtbl";
    std::set<std::string> names;
    for (const auto &[off, m] : virtuals) {
      if (off % pointer_size_ != 0 || off > (1u << 20)) continue;
      std::string n = m.first;
      for (int k = 2; !names.insert(n).second; ++k) n = m.first + "_" + std::to_string(k);
      vt.fields.push_back({n, g_.add(PointerType{type(m.second), pointer_size_, PointerKind::Pointer}), off * 8, 0});
      vt.size = std::max<std::uint64_t>(vt.size, off + pointer_size_);
    }
    if (vt.size == 0) vt.size = pointer_size_;
    const TypeId vtid = g_.add(std::move(vt));
    agg.fields.insert(agg.fields.begin(), Field{"vftable", g_.add(PointerType{vtid, pointer_size_, PointerKind::Pointer}), 0, 0});
  }
  return agg;
}

types::Type TypeImporter::build_enum(const Aggregate &a) {
  using namespace types;
  EnumType e;
  e.name = std::string(tag_name(a.name));
  e.complete = !(a.props & cv::kPropForwardRef);
  e.size = std::max<std::uint32_t>(1, clamp32(byte_size(a.underlying)));
  e.is_signed = is_signed_integer(a.underlying);
  if (!e.complete) return e;
  std::unordered_set<std::uint32_t> seen;
  std::uint32_t list = a.fields;
  while (list >= cv::kFirstNonSimple && seen.insert(list).second && seen.size() <= kMaxFieldLists) {
    TypeRecord r = tpi_.record(list);
    if (r.kind != cv::LF_FIELDLIST) break;
    list = 0;
    Cursor c(r.data, false);
    while (c.remaining() >= 2) {
      std::uint8_t b = r.data[c.pos()];
      if (b >= 0xf0) {
        c.skip(std::min<std::size_t>(std::max(1, b & 0x0f), c.remaining()));
        continue;
      }
      if (!charge(0)) break;
      std::uint16_t leaf = c.u16();
      if (leaf == cv::LF_ENUMERATE) {
        c.u16();
        Numeric v = read_numeric(c);
        std::int64_t value = std::int64_t(v.bits);
        // Sign-extend to the enum's width when it is signed but the value
        // was written unsigned.
        if (e.is_signed && !v.is_signed && e.size < 8) {
          unsigned shift = 64 - 8 * e.size;
          value = std::int64_t(v.bits << shift) >> shift;
        }
        e.values.push_back({std::string(read_name(c)), value});
      } else if (leaf == cv::LF_INDEX) {
        c.u16();
        list = c.u32();
      } else {
        break;
      }
    }
  }
  return e;
}

std::optional<types::FunctionType> TypeImporter::function(std::uint32_t ti) {
  using namespace types;
  if (ti < cv::kFirstNonSimple) return std::nullopt;
  TypeRecord r = tpi_.record(ti);
  if (r.kind != cv::LF_PROCEDURE && r.kind != cv::LF_MFUNCTION) return std::nullopt;
  Cursor c(r.data, false);
  FunctionType f;
  std::uint32_t this_type = 0;
  std::uint32_t ret = c.u32();
  if (r.kind == cv::LF_MFUNCTION) {
    c.u32();  // class
    this_type = c.u32();
  }
  std::uint8_t cc = c.u8();
  c.u8();   // function attributes
  c.u16();  // parameter count
  std::uint32_t args = c.u32();
  f.ret = type(ret);
  f.cc = call_conv(cc);
  if (this_type && this_type != cv::T_NOTYPE) {
    // CodeView's `this` is `T *const`; DWARF from clang (and the C++ type of
    // the expression) has no const on the pointer itself, so drop it.
    TypeRecord tr = tpi_.record(this_type);
    if (tr.kind == cv::LF_POINTER) {
      Cursor tc(tr.data, false);
      types::Type p = build_pointer(tc);
      if (auto *q = p.as<types::QualifiedType>()) p = std::as_const(g_).at(q->target);
      f.params.push_back({"this", g_.add(std::move(p))});
    } else {
      f.params.push_back({"this", type(this_type)});
    }
  }
  TypeRecord ar = tpi_.record(args);
  if (ar.kind == cv::LF_ARGLIST) {
    Cursor ac(ar.data, false);
    std::uint32_t n = ac.u32();
    if (n > ac.remaining() / 4) throw FormatError("argument list longer than its record");
    for (std::uint32_t i = 0; i < n; ++i) {
      std::uint32_t at = ac.u32();
      // A trailing T_NOTYPE marks a variadic function.
      if (at == cv::T_NOTYPE && i + 1 == n) {
        f.varargs = true;
        break;
      }
      if (!charge(ti)) break;
      f.params.push_back({std::string(), type(at)});
    }
  } else if (args >= cv::kFirstNonSimple) {
    warn(ti, "procedure without an argument list");
  }
  return f;
}

types::Type TypeImporter::build(std::uint32_t ti) {
  using namespace types;
  TypeRecord r = tpi_.record(ti);
  Cursor c(r.data, false);
  switch (r.kind) {
    case cv::LF_MODIFIER: {
      std::uint32_t target = c.u32();
      std::uint16_t mods = c.u16();
      std::uint8_t quals = 0;
      if (mods & cv::kModConst) quals |= kConst;
      if (mods & cv::kModVolatile) quals |= kVolatile;
      // Merge stacked modifiers, as the DWARF importer merges qualifiers.
      for (int k = 0; k < kMaxDepth && target >= cv::kFirstNonSimple; ++k) {
        TypeRecord inner = tpi_.record(target);
        if (inner.kind != cv::LF_MODIFIER) break;
        Cursor ic(inner.data, false);
        std::uint32_t next = ic.u32();
        std::uint16_t m = ic.u16();
        if (m & cv::kModConst) quals |= kConst;
        if (m & cv::kModVolatile) quals |= kVolatile;
        target = next;
      }
      return QualifiedType{type(target), quals};
    }
    case cv::LF_POINTER: return build_pointer(c);
    case cv::LF_ARRAY: {
      std::uint32_t elem = c.u32();
      c.u32();  // index type
      std::uint64_t size = read_numeric(c).bits;
      std::uint64_t esize = byte_size(elem);
      return ArrayType{type(elem), esize ? size / esize : 0};
    }
    case cv::LF_CLASS:
    case cv::LF_STRUCTURE:
    case cv::LF_INTERFACE:
    case cv::LF_CLASS2:
    case cv::LF_STRUCTURE2:
    case cv::LF_INTERFACE2:
    case cv::LF_UNION: {
      auto a = aggregate_header(r);
      if (!a) throw FormatError("truncated aggregate record");
      Type t = build_aggregate(ti, *a);
      aggregates_.push_back({memo_.at(ti), pointer_size_});
      return t;
    }
    case cv::LF_ENUM: {
      auto a = aggregate_header(r);
      if (!a) throw FormatError("truncated enum record");
      return build_enum(*a);
    }
    case cv::LF_PROCEDURE:
    case cv::LF_MFUNCTION: return *function(ti);
    case cv::LF_BITFIELD: return QualifiedType{type(c.u32()), 0};
    case cv::LF_ALIAS: {
      std::uint32_t target = c.u32();
      std::string name(read_name(c));
      if (name.empty()) return QualifiedType{type(target), 0};
      return TypedefType{std::move(name), type(target)};
    }
    case 0: throw FormatError("type index out of range");
    default: throw FormatError("unsupported type record kind 0x" + [&] {
      char buf[8];
      std::snprintf(buf, sizeof buf, "%x", r.kind);
      return std::string(buf);
    }());
  }
}

void TypeImporter::import_all() {
  for (std::uint32_t ti = tpi_.begin(); ti < tpi_.end(); ++ti) {
    switch (tpi_.record(ti).kind) {
      case cv::LF_MODIFIER:
      case cv::LF_POINTER:
      case cv::LF_ARRAY:
      case cv::LF_CLASS:
      case cv::LF_STRUCTURE:
      case cv::LF_INTERFACE:
      case cv::LF_CLASS2:
      case cv::LF_STRUCTURE2:
      case cv::LF_INTERFACE2:
      case cv::LF_UNION:
      case cv::LF_ENUM:
      case cv::LF_PROCEDURE:
      case cv::LF_MFUNCTION:
      case cv::LF_ALIAS: type(ti); break;
      default: break;
    }
    if (work_.size() > 64) drain();
  }
  drain();
}

std::vector<types::TypeId> TypeImporter::finish() {
  drain();
  types::infer_packing(g_, store_, aggregates_);
  if (std::size_t n = g_.break_invalid_cycles())
    diags_.push_back({0, "broke " + std::to_string(n) + " invalid type cycles"});
  return store_.intern(g_);
}

}  // namespace revkit::debuginfo::pdb
