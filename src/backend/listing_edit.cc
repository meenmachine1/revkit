// The listing's edits as assertions (listing_edit.h, docs/listing-edit.md).

#include "listing_edit.h"

#include "define_type.h"
#include "type_record.h"

#include "revkit/cparse/cparse.h"
#include "revkit/types/print.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <set>

namespace revkit::backend {

namespace an = analysis;
using types::TypeId;
using types::TypeStore;

namespace {

std::string Hex(std::uint64_t v) {
  char buf[24];
  std::snprintf(buf, sizeof buf, "%llx", static_cast<unsigned long long>(v));
  return buf;
}

std::string Trim(std::string_view s) {
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.remove_prefix(1);
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.remove_suffix(1);
  return std::string(s);
}

bool CharSigned(const Program &p) { return p.language().id().starts_with("x86"); }

unsigned PointerSize(const Program &p) { return p.image().bits / 8; }

// Ghidra's built-in data types (and the fixed-size C names), so the
// listing's keys don't depend on what the program's headers define.
std::optional<TypeId> Builtin(TypeStore &s, const std::string &name, const Program &p) {
  static const struct {
    const char *name;
    std::uint32_t size;
    bool is_signed;
  } kInts[] = {
      {"byte", 1, false},    {"word", 2, false},    {"dword", 4, false},   {"qword", 8, false},
      {"sbyte", 1, true},    {"sword", 2, true},    {"sdword", 4, true},   {"sqword", 8, true},
      {"uint8_t", 1, false}, {"uint16_t", 2, false}, {"uint32_t", 4, false}, {"uint64_t", 8, false},
      {"int8_t", 1, true},   {"int16_t", 2, true},  {"int32_t", 4, true},  {"int64_t", 8, true},
  };
  for (const auto &i : kInts)
    if (name == i.name) return s.int_type(i.size, i.is_signed);
  if (name == "char") return s.int_type(1, CharSigned(p), types::IntRank::PlainChar);
  if (name == "float") return s.float_type(4, types::FloatKind::Float);
  if (name == "double") return s.float_type(8, types::FloatKind::Double);
  if (name == "bool") return s.bool_type(1);
  if (name == "pointer" || name == "void *" || name == "void*") return s.pointer_to(s.void_type(), PointerSize(p));
  if (name == "undefined") return s.undefined(1);
  if (name.size() == 10 && name.starts_with("undefined") && name[9] >= '1' && name[9] <= '8')
    return s.undefined(static_cast<std::uint32_t>(name[9] - '0'));
  return std::nullopt;
}

// The C spelling as the listing shows it: "uint32_t[4]", not "uint32_t [4]".
std::string Name(const TypeStore &s, TypeId id) {
  std::string n = types::type_name(s, id);
  for (std::size_t i; (i = n.find(" [")) != std::string::npos;) n.erase(i, 1);
  return n;
}

TypeId Strip(const TypeStore &s, TypeId id) { return s.strip_typedefs(id, true); }

bool CharLike(const types::IntType &i) {
  using types::IntRank;
  return i.rank == IntRank::PlainChar || i.rank == IntRank::Char || i.rank == IntRank::WChar ||
         i.rank == IntRank::Char8 || i.rank == IntRank::Char16 || i.rank == IntRank::Char32;
}

an::ValueFormat FormatOf(const TypeStore &s, TypeId id) {
  const types::Type &t = s.get(Strip(s, id));
  switch (t.kind()) {
    case types::Kind::Int: {
      const auto &i = *t.as<types::IntType>();
      if (CharLike(i)) return an::ValueFormat::character;
      return i.is_signed ? an::ValueFormat::signed_int : an::ValueFormat::unsigned_int;
    }
    case types::Kind::Bool: return an::ValueFormat::boolean;
    case types::Kind::Float: return an::ValueFormat::floating;
    case types::Kind::Pointer: return an::ValueFormat::pointer;
    case types::Kind::Enum: return an::ValueFormat::enumeration;
    case types::Kind::Aggregate: return an::ValueFormat::aggregate;
    case types::Kind::Array: {
      const types::Type &e = s.get(Strip(s, t.as<types::ArrayType>()->element));
      if (const auto *i = e.as<types::IntType>(); i && CharLike(*i)) return an::ValueFormat::string;
      return an::ValueFormat::aggregate;
    }
    default: return an::ValueFormat::hex;
  }
}

constexpr std::size_t kMaxFields = 4096;
constexpr std::size_t kMaxPointers = 4096;

// Offsets of every pointer in a value of `id` at `off`.
void Pointers(const TypeStore &s, TypeId id, std::uint64_t off, std::vector<std::uint64_t> &out) {
  if (out.size() >= kMaxPointers) return;
  const types::Type &t = s.get(Strip(s, id));
  if (t.kind() == types::Kind::Pointer) {
    out.push_back(off);
  } else if (const auto *a = t.as<types::AggregateType>()) {
    for (const types::Field &f : a->fields)
      if (f.bit_size == 0) Pointers(s, f.type, off + f.bit_offset / 8, out);
  } else if (const auto *a = t.as<types::ArrayType>()) {
    const std::uint64_t size = s.size_of(a->element);
    if (size == 0) return;
    for (std::uint64_t i = 0; i < a->count && out.size() < kMaxPointers; ++i) {
      const std::size_t before = out.size();
      Pointers(s, a->element, off + i * size, out);
      if (out.size() == before) break;  // no pointers in an element
    }
  }
}

// The fields a value of aggregate or array type shows, depth first.
void Fields(const TypeStore &s, TypeId id, std::uint64_t off, std::uint32_t depth, std::vector<an::DataField> &out) {
  if (depth > an::kMaxFieldDepth || out.size() >= kMaxFields) return;
  const types::Type &t = s.get(Strip(s, id));
  auto add = [&](const std::string &name, TypeId ft, std::uint64_t at, std::uint64_t size) {
    if (out.size() >= kMaxFields) return;
    out.push_back({at, size, name, Name(s, ft), FormatOf(s, ft), depth});
    const an::ValueFormat f = out.back().format;
    if (f == an::ValueFormat::aggregate) Fields(s, ft, at, depth + 1, out);
  };
  if (const auto *a = t.as<types::AggregateType>()) {
    for (const types::Field &f : a->fields) {
      const std::uint64_t size = f.bit_size ? (f.bit_size + 7) / 8 : s.size_of(f.type);
      add(f.name.empty() ? "(anonymous)" : f.name, f.type, off + f.bit_offset / 8, size);
    }
  } else if (const auto *a = t.as<types::ArrayType>()) {
    const std::uint64_t size = s.size_of(a->element);
    for (std::uint64_t i = 0; i < a->count && i < an::kMaxShownElements; ++i)
      add("[" + std::to_string(i) + "]", a->element, off + i * size, size);
  }
}

// The records `id` reaches that weren't interned from the program's own.
void Records(const TypeStore &store, TypeId root, const ProgramTypes &program,
             std::map<std::string, ParsedRetype::Def> &out) {
  auto by_hash = [&](TypeId x) {
    pb::TypeNodeRef r;
    r.set_hash(store.hash(x).hex());
    return r;
  };
  std::vector<TypeId> stack{root};
  std::set<TypeId> seen;
  while (!stack.empty()) {
    TypeId id = stack.back();
    stack.pop_back();
    if (!seen.insert(id).second || program.recorded(id)) continue;
    ParsedRetype::Def def;
    def.record = EncodeTypeRecord(store, id);
    *def.body.mutable_define_type()->mutable_type() = TypeNodeOf(store, id, by_hash);
    out.emplace(store.hash(id).hex(), std::move(def));
    types::Type t = store.get(id);
    types::for_each_ref(t, [&](TypeId &x, types::EdgeKind) { stack.push_back(x); });
  }
}

std::string ResolveType(const ParseCContext &c, const pb::TypeSpec &spec, TypeStore &store, ProgramTypes &program,
                        TypeId &out) {
  if (spec.has_type_hash()) {
    auto id = program.intern(spec.type_hash());
    if (!id) return "unknown type hash " + spec.type_hash() + " (not defined in this program)";
    out = *id;
    return {};
  }
  const std::string text = Trim(spec.c_declaration());
  if (text.empty()) return "data.type is required (a type_hash or a c_declaration)";
  if (text.size() > 65536) return "c_declaration is longer than 64 KiB";
  if (auto b = Builtin(store, text, c.program)) {
    out = *b;
    return {};
  }
  cparse::Options o;
  o.profile = ProgramProfile(c.program);
  o.lookup = [&](std::string_view key) { return program.lookup(key); };
  o.limits.wall_time = std::chrono::milliseconds(2000);
  cparse::Result result;
  std::optional<cparse::Declaration> d = cparse::parse_declaration(store, text, o, &result);
  if (!d) return "can't read the type \"" + text + "\"";
  if (d->function) return "\"" + text + "\" is a function type, not data";
  out = d->type;
  return {};
}

}  // namespace

void LayOutElement(const TypeStore &store, TypeId elem, an::DataSpec &spec) {
  spec.format = FormatOf(store, elem);
  spec.fields.clear();
  spec.pointers.clear();
  Fields(store, elem, 0, 1, spec.fields);
  Pointers(store, elem, 0, spec.pointers);
  std::sort(spec.pointers.begin(), spec.pointers.end());
  spec.pointers.erase(std::unique(spec.pointers.begin(), spec.pointers.end()), spec.pointers.end());
  if (spec.format != an::ValueFormat::aggregate) spec.fields.clear();
}

std::string ElementName(const TypeStore &store, TypeId elem) { return Name(store, elem); }

std::string ResolveListingEdit(const ParseCContext &c, const pb::ListingEdit &e, const EditBytes &read,
                               ListingEditKey &out) {
  const Program &p = c.program;
  if (!e.address().space().empty() && e.address().space() != "ram" && e.address().space() != "default")
    return "only the default space is supported, got \"" + e.address().space() + "\"";
  const std::uint64_t a = e.address().offset();
  const loader::Block *block = p.block_containing(a);
  if (!block) return "address 0x" + Hex(a) + " is not in memory";
  const std::uint64_t block_last = block->start + (block->size - 1);
  out.address = a;
  out.stored.mutable_listing_edit()->CopyFrom(e);
  an::UnitMark mark;
  switch (e.kind_case()) {
    case pb::ListingEdit::kClear: {
      const std::uint64_t n = e.clear().length();
      if (n == 0) return "clear.length must be at least 1";
      if (a + (n - 1) < a || !p.block_containing(a + (n - 1))) return "clear runs past the end of memory";
      mark.kind = an::UnitKind::clear;
      mark.length = n;
      break;
    }
    case pb::ListingEdit::kDisassemble: {
      const pb::Disassemble &d = e.disassemble();
      mark.kind = an::UnitKind::code;
      mark.length = 1;
      mark.function = d.function();
      switch (d.instruction_set()) {
        case pb::INSTRUCTION_SET_UNSPECIFIED: mark.isa = an::Isa::inherit; break;
        case pb::INSTRUCTION_SET_ARM: mark.isa = an::Isa::arm; break;
        case pb::INSTRUCTION_SET_THUMB: mark.isa = an::Isa::thumb; break;
        default: return "disassemble.instruction_set is unknown";
      }
      if (mark.isa != an::Isa::inherit && !p.language().id().starts_with("ARM:"))
        return "disassemble.instruction_set: the program's language has one instruction set";
      if (!block->initialized) return "address 0x" + Hex(a) + " has no bytes (uninitialized memory)";
      break;
    }
    case pb::ListingEdit::kData: {
      const pb::DefineData &d = e.data();
      // Uninitialized memory (.bss) takes data too, as in Ghidra (its
      // values show as ??), but a string whose length its bytes say needs them.
      if (!block->initialized && d.string() != pb::STRING_ENCODING_UNSPECIFIED && d.layout() != pb::STRING_LAYOUT_FIXED)
        return "address 0x" + Hex(a) + " has no bytes (uninitialized memory) to find the string's length in";
      TypeStore store;
      ProgramTypes program(c.names, c.closure, store);
      an::DataSpec spec;
      spec.pointer_size = static_cast<std::uint8_t>(PointerSize(p));
      TypeId elem, item;
      std::uint64_t size = 0;
      const bool big = p.image().endian == loader::Endian::big;
      if (d.string() != pb::STRING_ENCODING_UNSPECIFIED) {
        unsigned unit = 1;
        switch (d.string()) {
          case pb::STRING_ENCODING_UTF8:
            spec.string = an::StringKind::utf8;
            elem = store.int_type(1, CharSigned(p), types::IntRank::PlainChar);
            break;
          case pb::STRING_ENCODING_UTF16:
            spec.string = an::StringKind::utf16;
            unit = 2;
            elem = store.int_type(2, false, types::IntRank::Char16);
            break;
          case pb::STRING_ENCODING_UTF32:
            spec.string = an::StringKind::utf32;
            unit = 4;
            elem = store.int_type(4, false, types::IntRank::Char32);
            break;
          default: return "data.string is unknown";
        }
        auto uint_at = [&](std::uint64_t at, unsigned n) -> std::optional<std::uint64_t> {
          const std::string b = read(at, n);
          if (b.size() < n) return std::nullopt;
          std::uint64_t v = 0;
          for (unsigned i = 0; i < n; ++i)
            v |= std::uint64_t{static_cast<unsigned char>(b[big ? n - 1 - i : i])} << (8 * i);
          return v;
        };
        switch (d.layout()) {
          case pb::STRING_LAYOUT_UNSPECIFIED:
          case pb::STRING_LAYOUT_TERMINATED: {
            spec.layout = an::StringLayout::terminated;
            const std::uint64_t limit = std::min<std::uint64_t>(kMaxStringScan, block_last - a + 1);
            const std::string b = read(a, static_cast<std::size_t>(limit));
            std::uint64_t n = 0;
            bool found = false;
            for (; (n + 1) * unit <= b.size(); ++n) {
              bool zero = true;
              for (unsigned i = 0; i < unit; ++i) zero = zero && b[n * unit + i] == 0;
              if (zero) {
                found = true;
                break;
              }
            }
            if (!found) return "no terminating NUL within " + std::to_string(limit) + " bytes of 0x" + Hex(a);
            size = (n + 1) * unit;
            break;
          }
          case pb::STRING_LAYOUT_FIXED:
            spec.layout = an::StringLayout::fixed;
            if (d.count() == 0) return "data.count: a fixed-length string needs its length in characters";
            if (d.count() > kMaxDataBytes / unit) return "data.count is too large";
            size = d.count() * unit;
            break;
          case pb::STRING_LAYOUT_PASCAL:
          case pb::STRING_LAYOUT_PASCAL16: {
            const unsigned prefix = d.layout() == pb::STRING_LAYOUT_PASCAL ? 1 : 2;
            spec.layout = prefix == 1 ? an::StringLayout::pascal : an::StringLayout::pascal16;
            auto n = uint_at(a, prefix);
            if (!n) return "no length prefix at 0x" + Hex(a);
            size = prefix + *n * unit;
            break;
          }
          default: return "data.layout is unknown";
        }
        spec.count = spec.layout == an::StringLayout::pascal || spec.layout == an::StringLayout::pascal16 ? size : size / unit;
        if (spec.layout == an::StringLayout::pascal || spec.layout == an::StringLayout::pascal16) {
          // The prefix and the characters: bytes to the decompiler.
          item = store.array_of(store.int_type(1, false, types::IntRank::Char), size);
        } else {
          item = store.array_of(elem, spec.count);
        }
        spec.format = an::ValueFormat::character;
        spec.collapsed = true;
      } else {
        if (auto err = ResolveType(c, d.type(), store, program, elem); !err.empty()) return "data.type: " + err;
        const std::uint64_t esize = store.size_of(elem);
        if (esize == 0) return "data.type " + types::type_name(store, elem) + " has no size";
        spec.count = d.count();
        if (spec.count > 0 && spec.count > kMaxDataBytes / esize) return "data.count is too large";
        item = spec.count > 0 ? store.array_of(elem, spec.count) : elem;
        size = spec.count > 0 ? spec.count * esize : esize;
        spec.collapsed = spec.count > 0;
        LayOutElement(store, elem, spec);
      }
      if (size == 0) return "the data would be empty";
      if (size > kMaxDataBytes) return "the data is larger than 16 MiB";
      if (a + (size - 1) < a || a + (size - 1) > block_last)
        return "the data (" + std::to_string(size) + " bytes) runs past the end of block " + block->name;
      if (d.has_collapsed()) spec.collapsed = d.collapsed();
      spec.type = store.hash(elem).hex();
      spec.type_name = Name(store, elem);
      spec.element = store.size_of(elem);
      spec.item_type = store.hash(item).hex();
      spec.item_name = Name(store, item);
      Records(store, item, program, out.types);
      mark.kind = an::UnitKind::data;
      mark.length = size;
      mark.data = std::move(spec);
      pb::DefineData *s = out.stored.mutable_listing_edit()->mutable_data();
      s->set_size(size);
      s->set_type_hash(mark.data.type);
      s->set_type_name(mark.data.type_name);
      s->set_collapsed(mark.data.collapsed);
      break;
    }
    case pb::ListingEdit::KIND_NOT_SET: return "listing_edit needs clear, disassemble or data";
  }
  out.sub = an::unit_sub(mark);
  out.value = facts::encode_to_string(mark);
  return {};
}

std::string ResolveMutability(const Program &p, const pb::SetMutability &m, ListingEditKey &out) {
  const std::uint64_t a = m.address().offset();
  if (!m.address().space().empty() && m.address().space() != "ram" && m.address().space() != "default")
    return "only the default space is supported, got \"" + m.address().space() + "\"";
  if (!p.block_containing(a)) return "address 0x" + Hex(a) + " is not in memory";
  if (m.length() == 0) return "mutability.length must be at least 1";
  if (a + (m.length() - 1) < a || !p.block_containing(a + (m.length() - 1))) return "the range runs past the end of memory";
  an::MutabilityMark mark;
  mark.length = m.length();
  switch (m.mutability()) {
    case pb::MUTABILITY_DEFAULT: mark.kind = an::MutabilityKind::as_map; break;
    case pb::MUTABILITY_NORMAL: mark.kind = an::MutabilityKind::normal; break;
    case pb::MUTABILITY_CONSTANT: mark.kind = an::MutabilityKind::constant; break;
    case pb::MUTABILITY_VOLATILE: mark.kind = an::MutabilityKind::is_volatile; break;
    default: return "mutability.mutability is required";
  }
  out.address = a;
  out.sub = an::hex_length(m.length());
  out.value = facts::encode_to_string(mark);
  out.stored.mutable_mutability()->CopyFrom(m);
  return {};
}

std::string DataMnemonic(const an::DataSpec &s) {
  if (s.string != an::StringKind::none)
    return s.string == an::StringKind::utf8 ? (s.layout == an::StringLayout::pascal || s.layout == an::StringLayout::pascal16 ? "p_string" : "ds")
           : s.string == an::StringKind::utf16 ? "unicode"
                                               : "unicode32";
  if (s.count > 0) return s.item_name;
  switch (s.format) {
    case an::ValueFormat::unsigned_int:
    case an::ValueFormat::signed_int: {
      static const char *kU[] = {"", "byte", "word", "", "dword", "", "", "", "qword"};
      static const char *kS[] = {"", "sbyte", "sword", "", "sdword", "", "", "", "sqword"};
      if (s.element <= 8 && *(s.format == an::ValueFormat::signed_int ? kS : kU)[s.element] != 0 &&
          (s.type_name.ends_with("int8_t") || s.type_name.ends_with("int16_t") || s.type_name.ends_with("int32_t") ||
           s.type_name.ends_with("int64_t")))
        return (s.format == an::ValueFormat::signed_int ? kS : kU)[s.element];
      return s.type_name;
    }
    case an::ValueFormat::pointer: return "addr";
    default: return s.type_name;
  }
}

std::string FormatValue(an::ValueFormat format, std::string_view bytes, bool big_endian) {
  const std::size_t n = bytes.size();
  if (n == 0) return "??";
  std::uint64_t v = 0;
  if (n <= 8)
    for (std::size_t i = 0; i < n; ++i)
      v |= std::uint64_t{static_cast<unsigned char>(bytes[big_endian ? n - 1 - i : i])} << (8 * i);
  char buf[64];
  switch (format) {
    case an::ValueFormat::signed_int: {
      if (n > 8) break;
      std::int64_t s = static_cast<std::int64_t>(v << (64 - 8 * n)) >> (64 - 8 * n);
      if (s < 0) std::snprintf(buf, sizeof buf, "-%llxh", static_cast<unsigned long long>(-static_cast<__int128>(s)));
      else std::snprintf(buf, sizeof buf, "%llxh", static_cast<unsigned long long>(s));
      return buf;
    }
    case an::ValueFormat::floating:
      if (n == 4) {
        float f;
        std::uint32_t u = static_cast<std::uint32_t>(v);
        std::memcpy(&f, &u, 4);
        std::snprintf(buf, sizeof buf, "%g", static_cast<double>(f));
        return buf;
      }
      if (n == 8) {
        double f;
        std::memcpy(&f, &v, 8);
        std::snprintf(buf, sizeof buf, "%g", f);
        return buf;
      }
      break;
    case an::ValueFormat::character:
      if (n == 1 && v >= 0x20 && v < 0x7f) {
        if (v == '\'' || v == '\\') std::snprintf(buf, sizeof buf, "'\\%c'", static_cast<char>(v));
        else std::snprintf(buf, sizeof buf, "'%c'", static_cast<char>(v));
        return buf;
      }
      break;
    case an::ValueFormat::boolean:
      if (n <= 8) return v == 0 ? "false" : v == 1 ? "true" : std::to_string(v);
      break;
    default: break;
  }
  if (n > 8) return "??";
  std::snprintf(buf, sizeof buf, "%0*llxh", static_cast<int>(2 * n), static_cast<unsigned long long>(v));
  return buf;
}

}  // namespace revkit::backend
