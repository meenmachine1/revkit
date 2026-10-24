#include "revkit/cparse/archive.h"

#include "revkit/types/describe.h"
#include "revkit/types/print.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <deque>
#include <functional>
#include <map>
#include <set>

namespace revkit::cparse {

using types::AggregateKind;
using types::AggregateType;
using types::EnumType;
using types::Field;
using types::Type;
using types::TypeId;
using types::TypeStore;

namespace {

// Types every compiler (and the parser) provides itself: written by name,
// never defined.
bool builtin_key(const std::string &key) {
  return key == "typedef __builtin_va_list" || key == "struct __va_list_tag" || key == "struct __va_list";
}

std::string hex(std::uint64_t v) {
  char buf[24];
  std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(v));
  return buf;
}

// The layout a parse must reproduce: size, explicit alignment, and every
// member's bit offset, width and size (so a member type laid out wrongly
// shows here too); an enum's size, signedness and values.
std::string shape(const TypeStore &s, TypeId id) {
  const TypeId x = s.strip_typedefs(id, false);
  const Type &t = s.get(x);
  std::string out;
  if (const auto *a = t.as<AggregateType>()) {
    out = "a" + std::to_string(int(a->kind)) + ":" + std::to_string(a->size) + ":" + std::to_string(a->alignment) +
          (a->complete ? "" : "?");
    for (const auto &f : a->fields)
      out += "," + std::to_string(f.bit_offset) + ":" + std::to_string(f.bit_size) + ":" +
             std::to_string(s.size_of(f.type));
  } else if (const auto *e = t.as<EnumType>()) {
    out = "e" + std::to_string(e->size) + (e->is_signed ? "s" : "u");
    for (const auto &v : e->values) out += "," + std::to_string(v.value);
  } else {
    out = "t" + std::to_string(s.size_of(x));
  }
  return out;
}

const char *keyword(AggregateKind k) { return k == AggregateKind::Union ? "union" : "struct"; }

struct Writer {
  const TypeStore &s;
  const ArchiveOptions &opt;
  types::PrintOptions popt;

  std::map<std::string, TypeId> chosen;  // key -> the definition written
  std::vector<std::string> order;        // keys with a definition, in header order
  std::vector<std::string> declared;     // struct/union keys declared before use (or never defined)
  std::map<std::string, std::set<std::string>> before;    // keys whose definition must come first
  std::map<std::string, std::set<std::string>> mentions;  // structs and unions a definition names
  std::set<std::uint32_t> undefined_sizes;
  bool uses_bool = false;
  // The compiler's own types (va_list's), written out only for parsers
  // that don't define them (Ghidra's): key -> type, tags before typedefs.
  std::vector<std::pair<std::string, TypeId>> builtins;
  std::vector<std::string> notes;

  // Forms: 0 natural; 1..4 #pragma pack(1, 2, 4, 8); 5 explicit offsets
  // (structs) / packed (enums).
  std::map<std::string, int> level;
  std::set<std::string> gave_up;

  Writer(const TypeStore &store, const ArchiveOptions &o) : s(store), opt(o) {
    popt.inline_anonymous = true;
    popt.offset_comments = true;
    popt.calling_conventions = true;
  }

  bool c89() const { return opt.dialect == Dialect::C89; }

  // C89 has no `long long`: GCC and clang take it under __extension__
  // (which the header defines away for other compilers).
  std::string ext(std::string text) const {
    if (c89() && text.find("long long") != std::string::npos) return "__extension__ " + text;
    return text;
  }

  // Unnamed bitfields covering `bits` from bit `pos`: to the next byte, then
  // whole bytes (as few bitfields as it can), then what is left. Compilers
  // record no member for them, so they only move what follows. In C89 they
  // are of the target's int, at most its width; in the decompiler's view
  // whole bytes are members named as its C names them (field_0x10).
  std::string gap(std::uint64_t pos, std::uint64_t bits) const {
    std::string out;
    auto add = [&](const char *type, std::uint64_t n) {
      out += "    " + std::string(type) + " : " + std::to_string(n) + ";\n";
      pos += n;
      bits -= n;
    };
    const char *small = c89() ? "unsigned int" : "unsigned char";
    if (pos % 8 && bits) add(small, std::min<std::uint64_t>(8 - pos % 8, bits));
    if (opt.decompiler_view) {
      for (; bits >= 8; pos += 8, bits -= 8) out += "    unsigned char " + types::gap_field_name(pos / 8) + ";\n";
    } else if (c89()) {
      const std::uint64_t int_bits = std::max<std::uint64_t>(16, std::uint64_t(opt.profile.rules.int_size) * 8);
      while (bits >= int_bits) add("unsigned int", int_bits);
      if (bits >= 8) add("unsigned int", bits / 8 * 8);
    } else {
      while (bits >= 64) add("unsigned long long", 64);
      if (bits >= 32) add("unsigned int", 32);
      if (bits >= 16) add("unsigned short", 16);
      if (bits >= 8) add("unsigned char", 8);
    }
    if (bits) add(small, bits);
    return out;
  }

  // An aggregate's members as written: its fields (in the decompiler's
  // view, those it keeps, under its names, and a byte member for each byte
  // none covers).
  struct Member {
    Field field;      // the field, named as written
    bool gap = false; // a byte no field covers (field.bit_offset)
  };
  bool viewed(const AggregateType &a) const { return opt.decompiler_view && !a.name.empty(); }
  std::vector<Member> members(const AggregateType &a) const {
    std::vector<Member> out;
    if (!viewed(a)) {
      // C89 has no anonymous members (named as the decompiler names them)
      // and no flexible array members (left out).
      for (std::size_t i = 0; i < a.fields.size(); ++i) {
        Field f = a.fields[i];
        if (c89() && !f.bit_size && s.size_of(f.type) == 0 && s.get(s.strip_typedefs(f.type)).as<types::ArrayType>())
          continue;
        if (c89() && f.name.empty() && !f.bit_size) f.name = "field_" + std::to_string(i);
        out.push_back({std::move(f), false});
      }
      return out;
    }
    const bool is_union = a.kind == AggregateKind::Union;
    std::uint64_t covered = 0;  // bytes before this are covered
    auto gaps_to = [&](std::uint64_t byte) {
      for (; covered < byte; ++covered) {
        Member m;
        m.gap = true;
        m.field.name = types::gap_field_name(covered);
        m.field.bit_offset = covered * 8;
        out.push_back(std::move(m));
      }
    };
    for (const types::DecompilerField &d : types::decompiler_fields(s, a)) {
      Field f = a.fields[d.index];
      f.name = d.name;
      if (!is_union) {
        const std::uint64_t first = f.bit_offset / 8;
        const std::uint64_t end = f.bit_size ? (f.bit_offset + f.bit_size + 7) / 8 : first + s.size_of(f.type);
        gaps_to(first);
        covered = std::max(covered, end);
      }
      out.push_back({std::move(f), false});
    }
    if (!is_union && a.complete) gaps_to(a.size);
    return out;
  }

  std::string member_text(const Member &m) const {
    if (!m.gap) return types::field_definition(s, m.field, 1, popt);
    char off[24];
    std::snprintf(off, sizeof off, "0x%llx", static_cast<unsigned long long>(m.field.bit_offset / 8));
    return "    unsigned char " + m.field.name + ";" + (popt.offset_comments ? std::string(" /* ") + off + " */" : "") + "\n";
  }

  bool complete_aggregate(TypeId id) const {
    const auto *a = s.get(id).as<AggregateType>();
    return a && a->complete;
  }

  void collect(std::span<const TypeId> roots) {
    std::map<std::string, std::vector<TypeId>> defs;
    std::set<TypeId> root_set(roots.begin(), roots.end());
    std::deque<TypeId> work(roots.begin(), roots.end());
    std::set<TypeId> seen(roots.begin(), roots.end());
    while (!work.empty()) {
      const TypeId id = work.front();
      work.pop_front();
      Type t = s.get(id);
      if (const auto *u = t.as<types::UndefinedType>()) undefined_sizes.insert(u->size);
      if (t.as<types::BoolType>()) uses_bool = true;
      if (std::string key = types::named_key(s, id); !key.empty()) defs[key].push_back(id);
      types::for_each_ref(t, [&](TypeId &r, types::EdgeKind) {
        if (seen.insert(r).second) work.push_back(r);
      });
    }
    // va_list's tag is the compiler's own where __builtin_va_list names it
    // (GCC on AArch64 records va_list as the struct itself: written out).
    const bool builtin_va_list = defs.contains("typedef __builtin_va_list");
    for (auto &[key, ids] : defs) {
      if (key == "typedef __builtin_va_list" || (builtin_va_list && builtin_key(key))) {
        builtins.emplace_back(key, ids.front());
        continue;
      }
      if (key.starts_with("typedef ") && opt.provided.contains(key.substr(8))) continue;  // the includer's
      if (key.find("::") != std::string::npos || key.starts_with("class ")) {
        notes.push_back(key + ": C++ types aren't written to archives (C headers); left out");
        continue;
      }
      // A complete definition, a root, then the lowest hash.
      std::sort(ids.begin(), ids.end(), [&](TypeId a, TypeId b) {
        auto rank = [&](TypeId x) {
          const bool incomplete = s.get(x).as<AggregateType>() && !complete_aggregate(x);
          return std::make_tuple(incomplete, !root_set.contains(x), s.hash(x).hex());
        };
        return rank(a) < rank(b);
      });
      chosen.emplace(key, ids.front());
      std::size_t definitions = 0;
      for (TypeId x : ids)
        if (!s.get(x).as<AggregateType>() || complete_aggregate(x)) ++definitions;
      if (definitions > 1)
        notes.push_back(key + ": " + std::to_string(definitions) + " definitions; the archive has " +
                        s.hash(ids.front()).hex() + ", and uses of the others name it");
    }
  }

  // What a definition needs before it: `out` gets the keys that must be
  // defined first, `named` the structs and unions it names.
  void deps(TypeId id, bool by_value, int depth, std::set<std::string> &out, std::set<std::string> &named) const {
    if (depth > 64) return;
    const Type &t = s.get(id);
    if (std::string key = types::named_key(s, id); !key.empty()) {
      auto it = chosen.find(key);
      if (it == chosen.end()) return;  // a builtin or left out
      const Type &ct = s.get(it->second);
      if (const auto *d = ct.as<types::TypedefType>()) {
        out.insert(key);
        if (by_value) deps(d->target, true, depth + 1, out, named);
      } else if (ct.as<AggregateType>()) {
        named.insert(key);
        if (by_value && complete_aggregate(it->second)) out.insert(key);
      } else {
        out.insert(key);  // enums: always defined before use (C has no enum forward declarations)
      }
      return;
    }
    if (const auto *p = t.as<types::PointerType>()) deps(p->target, false, depth + 1, out, named);
    else if (const auto *a = t.as<types::ArrayType>()) deps(a->element, true, depth + 1, out, named);
    else if (const auto *q = t.as<types::QualifiedType>()) deps(q->target, by_value, depth + 1, out, named);
    else if (const auto *f = t.as<types::FunctionType>()) {
      deps(f->ret, false, depth + 1, out, named);
      for (const auto &p : f->params) deps(p.type, false, depth + 1, out, named);
    } else if (const auto *g = t.as<AggregateType>()) {
      for (const auto &f : g->fields) deps(f.type, true, depth + 1, out, named);
    }
  }

  void plan() {
    for (const auto &[key, id] : chosen) {
      std::set<std::string> &b = before[key], &m = mentions[key];
      const Type &t = s.get(id);
      if (const auto *d = t.as<types::TypedefType>()) deps(d->target, false, 0, b, m);
      else if (const auto *a = t.as<AggregateType>())
        for (const auto &f : a->fields) deps(f.type, true, 0, b, m);
      b.erase(key);
    }
    // Enums first (they need nothing), then by name, each after what it needs.
    std::vector<std::string> keys;
    for (const auto &[key, id] : chosen)
      if (!s.get(id).as<AggregateType>() || complete_aggregate(id)) keys.push_back(key);
    std::stable_sort(keys.begin(), keys.end(), [&](const std::string &a, const std::string &b) {
      return std::make_tuple(!a.starts_with("enum "), a) < std::make_tuple(!b.starts_with("enum "), b);
    });
    std::map<std::string, int> state;
    std::function<void(const std::string &)> visit = [&](const std::string &k) {
      int &st = state[k];
      if (st == 2) return;
      if (st == 1) {
        notes.push_back(k + ": its definition depends on itself; the header order may not compile");
        return;
      }
      st = 1;
      for (const std::string &d : before[k])
        if (chosen.contains(d) && (!s.get(chosen.at(d)).as<AggregateType>() || complete_aggregate(chosen.at(d))))
          visit(d);
      state[k] = 2;
      order.push_back(k);
    };
    for (const std::string &k : keys) visit(k);
    // Structs and unions named before their definition (or never defined)
    // are declared first, so no prototype's parameter list declares one.
    std::set<std::string> defined, fwd;
    for (const std::string &k : order) {
      for (const std::string &m : mentions[k])
        if (m != k && !defined.contains(m)) fwd.insert(m);
      defined.insert(k);
    }
    for (const auto &[key, id] : chosen)
      if (s.get(id).as<AggregateType>() && !complete_aggregate(id)) fwd.insert(key);
    declared.assign(fwd.begin(), fwd.end());
  }

  std::string aggregate_text(const std::string &key, const AggregateType &a, int lvl, bool &ok) const {
    const std::string name = key.substr(key.find(' ') + 1);
    std::string body;
    if (lvl == 5) {
      // Explicit offsets: a struct packed to 1 whose gaps are unnamed
      // bitfields. Under Microsoft's rules a bitfield takes a unit of its
      // type's size and the bitfields after it share the unit only when
      // their types are as wide, so a gap inside a unit is written in that
      // unit's type.
      const bool msvc = opt.profile.rules.bitfields == BitfieldModel::Msvc;
      std::uint64_t pos = 0, unit_end = 0, unit_size = 0;
      std::string unit_type;
      auto close_unit = [&] {
        if (unit_size) pos = std::max(pos, unit_end);
        unit_size = 0;
      };
      std::vector<Field> fields;  // gaps are the gap()'s here
      for (const Member &m : members(a))
        if (!m.gap) fields.push_back(m.field);
      for (const auto &f : fields) {
        if (msvc && f.bit_size) {
          const std::uint64_t n = s.size_of(f.type);
          const bool same_unit = unit_size == n && f.bit_offset >= pos && f.bit_offset + f.bit_size <= unit_end;
          if (!same_unit) {
            close_unit();
            const std::uint64_t start = f.bit_offset / 8 * 8;
            if (start < pos || f.bit_offset + f.bit_size > start + n * 8) {
              ok = false;
              break;
            }
            body += gap(pos, start - pos);
            pos = start;
            unit_size = n;
            unit_end = start + n * 8;
            unit_type = types::type_name(s, f.type);
          }
          if (f.bit_offset > pos)
            body += "    " + unit_type + " : " + std::to_string(f.bit_offset - pos) + ";\n";
          body += types::field_definition(s, f, 1, popt);
          pos = f.bit_offset + f.bit_size;
          continue;
        }
        close_unit();
        if (f.bit_offset < pos) {
          ok = false;
          break;
        }
        body += gap(pos, f.bit_offset - pos);
        body += types::field_definition(s, f, 1, popt);
        pos = f.bit_offset + (f.bit_size ? f.bit_size : s.size_of(f.type) * 8);
      }
      close_unit();
      if (a.size * 8 > pos) body += gap(pos, a.size * 8 - pos);
    } else {
      for (const Member &m : members(a)) body += member_text(m);
    }
    std::string out = std::string(keyword(a.kind)) + " " + name + " {\n" + body + "}";
    if (a.alignment) out += " __attribute__((aligned(" + std::to_string(a.alignment) + ")))";
    out += "; /* size " + hex(a.size) + " */\n";
    out = ext(std::move(out));
    if (lvl >= 1 && lvl <= 5) {
      const int pack = lvl == 5 ? 1 : 1 << (lvl - 1);
      out = "#pragma pack(push, " + std::to_string(pack) + ")\n" + out + "#pragma pack(pop)\n";
    }
    return out;
  }

  std::string form_of(const std::string &key) const {
    const Type &t = s.get(chosen.at(key));
    if (t.as<types::TypedefType>()) return "typedef";
    const int lvl = level.contains(key) ? level.at(key) : 0;
    if (t.as<EnumType>()) return lvl == 5 ? "packed" : "natural";
    if (lvl == 0) return "natural";
    if (lvl == 5) return "explicit";
    return "pack(" + std::to_string(1 << (lvl - 1)) + ")";
  }

  std::string definition_text(const std::string &key) const {
    const TypeId id = chosen.at(key);
    const Type &t = s.get(id);
    const int lvl = level.contains(key) ? level.at(key) : 0;
    if (const auto *a = t.as<AggregateType>()) {
      bool ok = true;
      std::string text = aggregate_text(key, *a, lvl, ok);
      return ok ? text : aggregate_text(key, *a, 0, ok);
    }
    if (const auto *e = t.as<EnumType>()) {
      std::string out = "enum ";
      if (lvl == 5) out += "__attribute__((packed)) ";
      out += e->name + " {\n" + (c89() ? enum_values_c89(*e) : types::enum_values(*e)) + "};";
      if (e->size != 4) out += " /* size " + std::to_string(e->size) + " */";
      return out + "\n";
    }
    return ext(types::definition(s, id, popt));
  }

  // C89's enumerators are ints: a value past INT_MAX that fits the enum's
  // unsigned size is written as the int of the same bits.
  long long c89_value(const EnumType &e, long long v) const {
    const unsigned bits = std::max(16u, opt.profile.rules.int_size * 8u);
    const long long hi = (1LL << (bits - 1)) - 1;
    if (v > hi && e.size * 8 <= bits && static_cast<unsigned long long>(v) < (1ULL << bits)) v -= 1LL << bits;
    return v;
  }
  std::string enum_values_c89(const EnumType &e) const {
    const unsigned bits = std::max(16u, opt.profile.rules.int_size * 8u);
    const long long lo = -(1LL << (bits - 1));
    std::string out;
    for (std::size_t i = 0; i < e.values.size(); ++i) {
      const long long v = c89_value(e, e.values[i].value);
      const std::string text = v == lo ? "(" + std::to_string(lo + 1) + " - 1)" : std::to_string(v);
      out += "    " + e.values[i].name + " = " + text + (i + 1 < e.values.size() ? ",\n" : "\n");
    }
    return out;
  }

  // The layout the header means to write for `id`: shape(), or in the
  // decompiler's view a named aggregate's members as written.
  std::string intended_shape(TypeId id) const {
    const TypeId x = s.strip_typedefs(id, false);
    if (const auto *e = s.get(x).as<EnumType>(); e && c89()) {
      // As enum_values_c89 writes the values (an int's bits).
      std::vector<long long> vals;
      bool negative = false;
      for (const auto &v : e->values) {
        vals.push_back(c89_value(*e, v.value));
        negative = negative || vals.back() < 0;
      }
      std::string out = "e" + std::to_string(e->size) + (e->is_signed || negative ? "s" : "u");
      for (long long v : vals) out += "," + std::to_string(v);
      return out;
    }
    const auto *a = s.get(x).as<AggregateType>();
    if (!a || a->name.empty()) return shape(s, id);
    std::string out = "a" + std::to_string(int(a->kind)) + ":" + std::to_string(a->size) + ":" +
                      std::to_string(a->alignment) + (a->complete ? "" : "?");
    for (const Member &m : members(*a))
      out += "," + std::to_string(m.field.bit_offset) + ":" + std::to_string(m.field.bit_size) + ":" +
             std::to_string(m.gap ? 1 : s.size_of(m.field.type));
    return out;
  }

  std::string sizeof_expr(const std::string &key) const {
    return key.starts_with("typedef ") ? key.substr(8) : key;
  }

  std::string render(std::map<std::string, std::uint32_t> *lines) const {
    const std::string stem = archive_stem(opt.name);
    std::string guard = "REVKIT_ARCHIVE_";
    for (char c : stem) guard += std::isalnum(static_cast<unsigned char>(c)) ? char(std::toupper(c)) : '_';
    guard += "_H";
    std::string out;
    out += "/* " + stem + ".h: a revkit type archive of " + std::to_string(order.size() + declared.size()) +
           " types" + (opt.functions.empty() ? std::string() : " and " + std::to_string(opt.functions.size()) + " functions") +
           ".\n";
    out += " * Data model: " + describe_profile(opt.profile) + ".\n";
    out += " * Each type's content hash is in " + stem + ".json. */\n";
    out += "#ifndef " + guard + "\n#define " + guard + "\n";
    if (c89())
      out += "\n/* C89 has no long long: GCC and clang take it under __extension__. */\n"
             "#if !defined(__GNUC__) && !defined(__extension__)\n#define __extension__\n#endif\n";
    std::string undefined;
    for (std::uint32_t n : undefined_sizes)
      if (!opt.provided.contains("undefined" + std::to_string(n)))
        undefined += n == 1 ? "typedef unsigned char undefined1;\n"
                            : "typedef unsigned char undefined" + std::to_string(n) + "[" + std::to_string(n) + "];\n";
    if (!undefined.empty())
      out += "\n/* Ghidra's undefined types, for compilers (revkit and Ghidra know them). */\n#if !defined(__revkit__)\n" +
             undefined + "#endif\n";
    if (!builtins.empty()) {
      std::vector<std::pair<std::string, TypeId>> b = builtins;
      std::stable_sort(b.begin(), b.end(), [](const auto &x, const auto &y) {
        return x.first.starts_with("typedef ") < y.first.starts_with("typedef ");
      });
      out += "\n/* The compiler's own va_list, for C parsers that don't define it (Ghidra's). */\n";
      out += "#if !defined(__GNUC__) && !defined(__clang__) && !defined(_MSC_VER) && !defined(__revkit__)\n";
      for (const auto &[key, id] : b) {
        if (const auto *a = s.get(id).as<AggregateType>()) {
          bool ok = true;
          out += aggregate_text(key, *a, 0, ok);
        } else {
          out += types::definition(s, id, popt);
        }
      }
      out += "#endif\n";
    }
    if (uses_bool && !opt.provided.contains("bool")) {
      if (c89())
        out += "\n#if !defined(__cplusplus) && !defined(bool) && !defined(REVKIT_BOOL)\n#define REVKIT_BOOL\n"
               "typedef unsigned char bool;\n#endif\n";
      else
        out += "\n#if !defined(__cplusplus) && !defined(bool) && (!defined(__STDC_VERSION__) || __STDC_VERSION__ < "
               "202311L)\n#define bool _Bool\n#endif\n";
    }
    auto line_now = [&] { return std::uint32_t(std::count(out.begin(), out.end(), '\n') + 1); };
    if (!declared.empty()) {
      out += "\n";
      for (const std::string &k : declared) {
        if (lines) lines->emplace(k, line_now());
        out += k + ";\n";
      }
    }
    for (const std::string &k : order) {
      out += "\n";
      if (lines) (*lines)[k] = line_now();
      out += definition_text(k);
    }
    if (!opt.functions.empty()) {
      out += "\n/* Functions */\n";
      for (const ArchiveFunction &f : opt.functions) {
        if (lines) (*lines)["function " + f.name] = line_now();
        out += ext(std::string(f.noreturn && !c89() ? "_Noreturn " : "") + types::declaration(s, f.type, f.name, popt) + ";\n");
      }
    }
    std::string asserts, check_stem;
    for (char c : stem) check_stem += std::isalnum(static_cast<unsigned char>(c)) ? c : '_';
    std::size_t checks = 0;
    for (const std::string &k : order) {
      const TypeId id = chosen.at(k);
      const TypeId under = s.strip_typedefs(id, true);
      const Type &u = s.get(under);
      if (u.as<types::FunctionType>() || u.as<types::VoidType>()) continue;
      if (const auto *a = u.as<AggregateType>(); a && !a->complete) continue;
      const std::uint64_t size = s.size_of(id);
      if (size == 0) continue;
      if (c89())  // an array of negative size where the size is wrong
        asserts += "typedef char rk_size_" + check_stem + "_" + std::to_string(++checks) + "[sizeof(" + sizeof_expr(k) +
                   ") == " + std::to_string(size) + " ? 1 : -1]; /* " + k + " */\n";
      else
        asserts += "_Static_assert(sizeof(" + sizeof_expr(k) + ") == " + std::to_string(size) + ", \"" + k + "\");\n";
    }
    if (!asserts.empty()) out += "\n" + asserts;
    out += "\n#endif /* " + guard + " */\n";
    return out;
  }
};

}  // namespace

std::string archive_stem(std::string_view name) {
  std::string out;
  for (char c : name) out += std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-' || c == '.' ? c : '_';
  while (!out.empty() && out.front() == '.') out.erase(out.begin());
  if (out.empty()) out = "types";
  return out;
}

std::string describe_profile(const Profile &p) {
  const LayoutRules &r = p.rules;
  std::string out = p.name + ": pointer " + std::to_string(r.pointer_size) + ", short " +
                    std::to_string(r.short_size) + ", int " + std::to_string(r.int_size) + ", long " +
                    std::to_string(r.long_size) + ", long long " + std::to_string(r.long_long_size) +
                    ", long double " + std::to_string(r.long_double_size) + ", wchar_t " +
                    std::to_string(r.wchar_size) + "; char " + (r.char_signed ? "signed" : "unsigned") + ", " +
                    (r.big_endian ? "big" : "little") + "-endian, " +
                    (r.bitfields == BitfieldModel::Msvc ? "Microsoft" : "GCC") + " bitfields";
  return out;
}

Archive write_archive(const TypeStore &store, std::span<const TypeId> roots, const ArchiveOptions &options) {
  Writer w(store, options);
  std::vector<TypeId> all(roots.begin(), roots.end());
  for (const ArchiveFunction &f : options.functions) all.push_back(f.type);
  w.collect(all);
  w.plan();

  Archive out;
  std::map<std::string, std::string> parsed_hash, parsed_shape;
  std::map<std::string, bool> parsed_noreturn;
  std::string text;
  std::vector<std::string> parse_notes;
  auto check = [&] {
    std::map<std::string, std::uint32_t> lines;
    text = w.render(&lines);
    TypeStore s2;
    Options o;
    o.profile = options.profile;
    o.limits.wall_time = std::chrono::milliseconds(60'000);
    const Source src{archive_stem(options.name) + ".h", text, false};
    Result r = parse(s2, std::span<const Source>(&src, 1), o);
    parsed_hash.clear();
    parsed_shape.clear();
    for (const auto &n : r.named) {
      parsed_hash.emplace(n.key, s2.hash(n.id).hex());
      parsed_shape.emplace(n.key, shape(s2, n.id));
    }
    parsed_noreturn.clear();
    for (const auto &p : r.prototypes) {
      parsed_hash.emplace("function " + p.name, s2.hash(p.type).hex());
      parsed_noreturn.emplace("function " + p.name, p.noreturn);
    }
    parse_notes.clear();
    for (const auto &d : r.diagnostics)
      if (d.severity == Severity::Error)
        parse_notes.push_back("line " + std::to_string(d.line) + ": " + d.text);
    return lines;
  };
  auto bad_layout = [&](const std::string &key) {
    auto it = parsed_shape.find(key);
    return it == parsed_shape.end() || it->second != w.intended_shape(w.chosen.at(key));
  };

  std::map<std::string, std::uint32_t> lines = check();
  for (int round = 0; round < 32; ++round) {
    std::vector<std::string> next;
    for (const std::string &k : w.order) {
      if (!bad_layout(k)) continue;
      const Type &t = store.get(w.chosen.at(k));
      if (!t.as<AggregateType>() && !t.as<EnumType>()) continue;
      bool waiting = false;
      for (const std::string &d : w.before[k]) waiting = waiting || (w.chosen.contains(d) && bad_layout(d));
      if (!waiting) next.push_back(k);
    }
    bool changed = false;
    for (const std::string &k : next) {
      if (w.gave_up.contains(k)) continue;
      int &lvl = w.level[k];
      const Type &t = store.get(w.chosen.at(k));
      int to = -1;  // -1: nothing left to try (the last form stays)
      if (const auto *e = t.as<EnumType>()) {
        if (lvl == 0 && e->size < 4) to = 5;
      } else {
        const auto &a = *t.as<AggregateType>();
        if (lvl == 0) to = a.packed ? 1 : 5;
        else if (lvl < 4) to = lvl + 1;
        else if (lvl == 4) to = 5;
        if (to == 5 && a.kind == AggregateKind::Union) to = -1;
      }
      if (to < 0) {
        w.gave_up.insert(k);
        continue;
      }
      lvl = to;
      changed = true;
    }
    if (!changed) break;
    lines = check();
  }

  auto add_entry = [&](const std::string &k, const std::string &form) {
    ArchiveEntry e;
    e.key = k;
    e.id = w.chosen.at(k);
    e.source_hash = store.hash(e.id).hex();
    auto it = parsed_hash.find(k);
    e.hash = it == parsed_hash.end() ? std::string() : it->second;
    e.size = store.size_of(e.id);
    e.line = lines.contains(k) ? lines.at(k) : 0;
    e.form = form;
    // The decompiler's view adds and renames members: only the layout counts.
    if (options.decompiler_view ? e.hash.empty() || bad_layout(k) : e.hash != e.source_hash) {
      ++out.mismatches;
      std::string why = e.hash.empty() ? "doesn't parse"
                        : bad_layout(k) ? "parses to another layout"
                                        : "parses to the same layout but another type (member names or types differ)";
      out.notes.push_back(k + ": " + why + " (" + e.form + ")");
    }
    out.entries.push_back(std::move(e));
  };
  for (const std::string &k : w.declared)
    if (const auto *a = store.get(w.chosen.at(k)).as<AggregateType>(); a && !a->complete) add_entry(k, "declaration");
  for (const std::string &k : w.order) add_entry(k, w.form_of(k));
  for (const ArchiveFunction &f : options.functions) {
    const std::string k = "function " + f.name;
    ArchiveEntry e;
    e.key = k;
    e.id = f.type;
    e.source_hash = store.hash(f.type).hex();
    auto it = parsed_hash.find(k);
    e.hash = it == parsed_hash.end() ? std::string() : it->second;
    e.line = lines.contains(k) ? lines.at(k) : 0;
    e.form = "prototype";
    e.noreturn = f.noreturn;
    if (e.hash != e.source_hash || parsed_noreturn[k] != f.noreturn) {
      ++out.mismatches;
      out.notes.push_back(k + ": " + (e.hash.empty() ? "doesn't parse" : "parses to another prototype"));
    }
    out.entries.push_back(std::move(e));
  }
  out.header = std::move(text);
  out.notes.insert(out.notes.begin(), w.notes.begin(), w.notes.end());
  for (const std::string &n : parse_notes) out.notes.push_back(n);
  return out;
}

}  // namespace revkit::cparse
