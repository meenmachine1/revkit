#include "revkit/types/print.h"

#include <cstdio>
#include <string>

namespace revkit::types {
namespace {

// Parameter lists nest (function pointers taking function pointers), and a
// type can mention the same subtype many times, so output can grow
// exponentially in the type's size. Past this depth, or once a printer has
// visited this many types, we print placeholders instead.
constexpr int kMaxDepth = 32;
constexpr std::size_t kMaxVisits = 4096;

std::string hex(std::uint64_t v) {
  char buf[24];
  std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(v));
  return buf;
}

std::string anon_name(const TypeStore &s, TypeId id, std::string_view what) {
  return "anon_" + std::string(what) + "_" + s.hash(id).hex().substr(0, 8);
}

const char *aggregate_keyword(AggregateKind k) {
  switch (k) {
    case AggregateKind::Struct: return "struct";
    case AggregateKind::Class: return "class";
    case AggregateKind::Union: return "union";
  }
  return "struct";
}

std::string int_name(const IntType &t, Style style) {
  const bool g = style == Style::Ghidra;
  const bool s = t.is_signed;
  switch (t.rank) {
    case IntRank::PlainChar: return "char";
    case IntRank::Char: return g ? (s ? "char" : "uchar") : (s ? "signed char" : "unsigned char");
    case IntRank::Short: return g ? (s ? "short" : "ushort") : (s ? "short" : "unsigned short");
    case IntRank::Int: return g ? (s ? "int" : "uint") : (s ? "int" : "unsigned int");
    case IntRank::Long: return g ? (s ? "long" : "ulong") : (s ? "long" : "unsigned long");
    case IntRank::LongLong:
      return g ? (s ? "longlong" : "ulonglong") : (s ? "long long" : "unsigned long long");
    case IntRank::Int128:
      return g ? (s ? "__int128" : "__int128 unsigned") : (s ? "__int128" : "unsigned __int128");
    case IntRank::WChar: return "wchar_t";
    case IntRank::Char8: return "char8_t";
    case IntRank::Char16: return "char16_t";
    case IntRank::Char32: return "char32_t";
    case IntRank::Fixed: break;
  }
  return (s ? "int" : "uint") + std::to_string(std::uint64_t(t.size) * 8) + "_t";
}

std::string float_name(const FloatType &t, Style style) {
  std::string base;
  switch (t.kind) {
    case FloatKind::Half: base = "_Float16"; break;
    case FloatKind::Float: base = "float"; break;
    case FloatKind::Double: base = "double"; break;
    case FloatKind::LongDouble: base = style == Style::Ghidra ? "longdouble" : "long double"; break;
    case FloatKind::Float128: base = "_Float128"; break;
  }
  if (!t.complex) return base;
  return style == Style::Ghidra ? "complex " + base : "_Complex " + base;
}

std::string qual_words(std::uint8_t q) {
  std::string out;
  auto add = [&](std::uint8_t bit, const char *w) {
    if (!(q & bit)) return;
    if (!out.empty()) out += ' ';
    out += w;
  };
  add(kConst, "const");
  add(kVolatile, "volatile");
  add(kRestrict, "restrict");
  add(kAtomic, "_Atomic");
  return out;
}

// Name of a type that has one (no declarator part), or empty.
std::string leaf_name(const TypeStore &s, TypeId id, const Type &t, Style style) {
  const bool c = style == Style::C;
  if (t.as<VoidType>()) return "void";
  if (t.as<BoolType>()) return "bool";
  if (auto *i = t.as<IntType>()) return int_name(*i, style);
  if (auto *f = t.as<FloatType>()) return float_name(*f, style);
  if (auto *u = t.as<UndefinedType>()) return "undefined" + std::to_string(u->size);
  if (auto *d = t.as<TypedefType>()) return d->name;
  if (auto *a = t.as<AggregateType>()) {
    const char *kw = aggregate_keyword(a->kind);
    std::string name = a->name.empty() ? anon_name(s, id, kw) : a->name;
    return c ? std::string(kw) + " " + name : name;
  }
  if (auto *e = t.as<EnumType>()) {
    std::string name = e->name.empty() ? anon_name(s, id, "enum") : e->name;
    return c ? "enum " + name : name;
  }
  return {};
}

std::string inline_definition(const TypeStore &s, TypeId id, int indent, int depth, const PrintOptions &opt);

class Printer {
 public:
  Printer(const TypeStore &s, const PrintOptions &o, int indent = 0) : s_(s), o_(o), indent_(indent) {}

  // C declarator syntax, peeling layers off the type from the outside in.
  std::string c_decl(TypeId id, std::string decl, int depth, bool name_params = false) const {
    if (exhausted()) return decl.empty() ? "..." : "... " + decl;
    std::uint8_t quals = 0;
    bool ptr_last = false;  // decl starts with a pointer operator
    for (std::size_t guard = 0; guard <= s_.size() && !exhausted(); ++guard) {
      const Type &t = s_.get(id);
      if (auto *q = t.as<QualifiedType>()) {
        quals |= q->quals;
        id = q->target;
        continue;
      }
      if (auto *d = t.as<TypedefType>(); d && o_.resolve_typedefs) {
        id = d->target;
        continue;
      }
      if (auto *p = t.as<PointerType>()) {
        std::string op = p->kind == PointerKind::LValueRef   ? "&"
                         : p->kind == PointerKind::RValueRef ? "&&"
                                                             : "*";
        std::string qs = qual_words(quals);
        quals = 0;
        op += qs;
        if (!qs.empty() && !decl.empty()) op += ' ';
        decl = op + decl;
        ptr_last = true;
        id = p->target;
        continue;
      }
      if (auto *a = t.as<ArrayType>()) {
        if (ptr_last) decl = "(" + decl + ")";
        decl += "[" + (a->count ? std::to_string(a->count) : std::string()) + "]";
        ptr_last = false;
        id = a->element;  // qualifiers carry over to the element type
        continue;
      }
      if (auto *f = t.as<FunctionType>()) {
        if (o_.calling_conventions && f->cc != CallConv::Default && f->cc != CallConv::Other) {
          const std::string kw = f->cc == CallConv::Ms64    ? "__attribute__((ms_abi))"
                                 : f->cc == CallConv::SysV ? "__attribute__((sysv_abi))"
                                                           : cc_name(f->cc);
          decl = decl.empty() ? kw : kw + " " + decl;
        }
        if (ptr_last) decl = "(" + decl + ")";
        decl += "(" + c_params(*f, depth, name_params) + ")";
        name_params = false;
        ptr_last = false;
        quals = 0;
        id = f->ret;
        continue;
      }
      std::string spec;
      if (o_.inline_anonymous && depth < 8) spec = inline_definition(s_, id, indent_, depth, o_);
      if (spec.empty()) spec = leaf_name(s_, id, t, Style::C);
      if (quals) spec = qual_words(quals) + " " + spec;
      return decl.empty() ? spec : spec + " " + decl;
    }
    return decl.empty() ? "..." : "... " + decl;
  }

  std::string c_params(const FunctionType &f, int depth, bool name_params) const {
    if (f.params.empty()) return f.varargs ? "..." : "void";
    if (depth >= kMaxDepth || exhausted()) return "...";
    std::string out;
    for (std::size_t i = 0; i < f.params.size(); ++i) {
      if (i) out += ", ";
      std::string name = f.params[i].name;
      if (name.empty() && name_params) name = "param_" + std::to_string(i + 1);
      out += c_decl(f.params[i].type, name, depth + 1);
    }
    if (f.varargs) out += ", ...";
    return out;
  }

  // Ghidra's DataType.getDisplayName() for the type.
  std::string g_name(TypeId id, int depth) const {
    if (depth >= kMaxDepth || exhausted()) return "undefined";
    for (std::size_t guard = 0; guard <= s_.size(); ++guard) {
      const Type &t = s_.get(id);
      if (auto *q = t.as<QualifiedType>()) {
        id = q->target;
        continue;
      }
      if (auto *d = t.as<TypedefType>(); d && o_.resolve_typedefs) {
        id = d->target;
        continue;
      }
      if (auto *p = t.as<PointerType>()) return g_name(p->target, depth + 1) + " *";
      if (t.as<ArrayType>()) {
        std::string dims;
        while (auto *a = s_.get(id).as<ArrayType>()) {
          dims += "[" + std::to_string(a->count) + "]";
          id = a->element;
          if (dims.size() > 4096) break;
        }
        return g_name(id, depth + 1) + dims;
      }
      if (auto *f = t.as<FunctionType>()) return g_func_name(*f, depth);
      return leaf_name(s_, id, t, Style::Ghidra);
    }
    return "undefined";
  }

  // DataTypeNamingUtil.generateMangledSignature().
  std::string g_func_name(const FunctionType &f, int depth) const {
    auto mangle = [&](TypeId id) {
      std::string out;
      for (char ch : g_name(id, depth + 1)) {
        if (ch == ' ') out += '_';
        else if (ch == '*') out += "ptr";
        else out += ch;
      }
      return out;
    };
    std::string out = "_func";
    if (f.cc != CallConv::Default) out += "_" + std::string(cc_name(f.cc));
    out += "_" + mangle(f.ret);
    for (const Param &p : f.params) out += "_" + mangle(p.type);
    if (f.varargs) out += "_varargs";
    return out;
  }

  static const char *cc_name(CallConv cc) {
    switch (cc) {
      case CallConv::Default: return "";
      case CallConv::Cdecl: return "__cdecl";
      case CallConv::Stdcall: return "__stdcall";
      case CallConv::Fastcall: return "__fastcall";
      case CallConv::Thiscall: return "__thiscall";
      case CallConv::Vectorcall: return "__vectorcall";
      case CallConv::Pascal: return "__pascal";
      case CallConv::Ms64: return "__ms_abi";
      case CallConv::SysV: return "__sysv_abi";
      case CallConv::Regcall: return "__regcall";
      case CallConv::Other: return "__unknowncc";
    }
    return "";
  }

  std::string g_prototype(const FunctionType &f, std::string_view name) const {
    std::string out = g_name(f.ret, 1) + " " + std::string(name) + "(";
    if (f.params.empty() && !f.varargs) out += "void";
    for (std::size_t i = 0; i < f.params.size(); ++i) {
      if (i) out += ", ";
      std::string pname = f.params[i].name;
      if (pname.empty()) pname = "param_" + std::to_string(i + 1);
      out += g_name(f.params[i].type, 1) + " " + pname;
    }
    if (f.varargs) out += f.params.empty() ? "..." : ", ...";
    return out + ")";
  }

 private:
  bool exhausted() const { return ++visits_ > kMaxVisits; }

  const TypeStore &s_;
  const PrintOptions &o_;
  int indent_ = 0;
  mutable std::size_t visits_ = 0;
};

void definition_body(const TypeStore &s, const AggregateType &a, int indent, int depth,
                     std::string &out, const PrintOptions &opt);

std::string field_line(const TypeStore &s, const Field &f, int indent, int depth, const PrintOptions &opt) {
  std::string pad(std::size_t(indent) * 4, ' ');
  std::string line = pad;
  const Type &ft = s.get(f.type);
  auto *anon = ft.as<AggregateType>();
  if (anon && anon->name.empty() && depth < 8) {
    line += aggregate_keyword(anon->kind);
    line += " {\n";
    definition_body(s, *anon, indent + 1, depth + 1, line, opt);
    line += pad + "}";
    if (opt.inline_anonymous && anon->alignment)
      line += " __attribute__((aligned(" + std::to_string(anon->alignment) + ")))";
    if (!f.name.empty()) line += " " + f.name;
  } else {
    PrintOptions o = opt;
    o.style = Style::C;
    line += Printer(s, o, indent).c_decl(f.type, f.name, depth);
  }
  if (f.bit_size) line += " : " + std::to_string(f.bit_size);
  line += ";";
  if (opt.offset_comments)
    line += f.bit_size || f.bit_offset % 8
                ? " /* " + hex(f.bit_offset / 8) + ":" + std::to_string(f.bit_offset % 8) + " */"
                : " /* " + hex(f.bit_offset / 8) + " */";
  return line + "\n";
}

void definition_body(const TypeStore &s, const AggregateType &a, int indent, int depth,
                     std::string &out, const PrintOptions &opt) {
  for (const Field &f : a.fields) out += field_line(s, f, indent, depth, opt);
}

std::string enum_body(const EnumType &e, int indent) {
  std::string pad(std::size_t(indent) * 4, ' ');
  std::string out;
  for (std::size_t i = 0; i < e.values.size(); ++i)
    out += pad + "    " + e.values[i].name + " = " + std::to_string(e.values[i].value) +
           (i + 1 < e.values.size() ? ",\n" : "\n");
  return out;
}

// An anonymous struct, union or enum written out where it is used; empty
// for anything else.
std::string inline_definition(const TypeStore &s, TypeId id, int indent, int depth, const PrintOptions &opt) {
  const Type &t = s.get(id);
  std::string pad(std::size_t(indent) * 4, ' ');
  if (auto *a = t.as<AggregateType>(); a && a->name.empty() && a->complete) {
    std::string out = std::string(aggregate_keyword(a->kind)) + " {\n";
    definition_body(s, *a, indent + 1, depth + 1, out, opt);
    out += pad + "}";
    if (a->alignment) out += " __attribute__((aligned(" + std::to_string(a->alignment) + ")))";
    return out;
  }
  if (auto *e = t.as<EnumType>(); e && e->name.empty() && e->complete && !e->values.empty())
    return "enum {\n" + enum_body(*e, indent) + pad + "}";
  return {};
}

}  // namespace

std::string type_name(const TypeStore &store, TypeId id, const PrintOptions &opt) {
  Printer p(store, opt);
  return opt.style == Style::Ghidra ? p.g_name(id, 0) : p.c_decl(id, "", 0);
}

std::string declaration(const TypeStore &store, TypeId id, std::string_view name,
                        const PrintOptions &opt) {
  Printer p(store, opt);
  if (opt.style == Style::Ghidra) return p.g_name(id, 0) + " " + std::string(name);
  return p.c_decl(id, std::string(name), 0);
}

std::string prototype(const TypeStore &store, TypeId fn, std::string_view name,
                      const PrintOptions &opt) {
  TypeId id = store.strip_typedefs(fn);
  const FunctionType *f = store.get(id).as<FunctionType>();
  if (!f) return declaration(store, fn, name, opt);
  Printer p(store, opt);
  if (opt.style == Style::Ghidra) return p.g_prototype(*f, name);
  return p.c_decl(id, std::string(name), 0, /*name_params=*/true);
}

std::string definition(const TypeStore &store, TypeId id) { return definition(store, id, PrintOptions{}); }

std::string field_definition(const TypeStore &store, const Field &field, int indent, const PrintOptions &opt) {
  PrintOptions o = opt;
  o.style = Style::C;
  return field_line(store, field, indent, 0, o);
}

std::string enum_values(const EnumType &e, int indent) { return enum_body(e, indent); }

std::string definition(const TypeStore &store, TypeId id, const PrintOptions &options) {
  const Type &t = store.get(id);
  PrintOptions opt = options;
  opt.style = Style::C;
  if (auto *a = t.as<AggregateType>()) {
    std::string head = leaf_name(store, id, t, Style::C);
    if (!a->complete) return head + ";\n";
    std::string out = head + " {\n";
    definition_body(store, *a, 1, 0, out, opt);
    out += "}";
    if (a->packed) out += " __attribute__((packed))";
    if (a->alignment) out += " __attribute__((aligned(" + std::to_string(a->alignment) + ")))";
    return out + "; /* size " + hex(a->size) + " */\n";
  }
  if (auto *e = t.as<EnumType>()) {
    std::string out = leaf_name(store, id, t, Style::C);
    if (!e->complete) return out + ";\n";
    out += " {\n" + enum_body(*e, 0);
    out += "};";
    if (e->size != 4) out += " /* size " + std::to_string(e->size) + " */";
    return out + "\n";
  }
  if (auto *d = t.as<TypedefType>())
    return "typedef " + Printer(store, opt).c_decl(d->target, d->name, 0) + ";\n";
  return type_name(store, id, opt);
}

}  // namespace revkit::types
