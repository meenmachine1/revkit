// The demangler analysis's prototypes (docs/demangle.md): a demangled
// function signature written as C, read by revkit::cparse for the
// program's target, and given to the decompiler.

#include "revkit/inputs/demangled.h"

#include "revkit/inputs/ghidra_types.h"
#include "revkit/types/print.h"

#include <cctype>
#include <map>

namespace revkit::inputs {
using demangle::Type;

// C, for one prototype: class names behind placeholders cparse looks up.
class CWriter {
 public:
  explicit CWriter(const cparse::Profile &profile) : profile_(&profile) {}

  bool ok() const { return ok_; }
  const std::vector<std::string> &classes() const { return classes_; }

  // `t` declaring `inner` ("" for an abstract declarator). A class by value
  // can't be written (its layout is unknown): fails.
  std::string decl(const Type &t, const std::string &inner, bool behind_pointer = false) {
    if (++depth_ > 32) ok_ = false;
    std::string out = write(t, inner, behind_pointer);
    --depth_;
    return out;
  }

  // A parameter: arrays and functions decay to pointers.
  std::string param(const Type &t, const std::string &name) {
    if (t.kind == Type::Kind::Array && !t.children.empty()) {
      Type p;
      p.kind = Type::Kind::Pointer;
      p.children.push_back(t.children[0]);
      return decl(p, name);
    }
    if (t.kind == Type::Kind::Function) {
      Type p;
      p.kind = Type::Kind::Pointer;
      p.children.push_back(t);
      return decl(p, name);
    }
    return decl(t, name);
  }

  std::string class_ref(const std::string &name) {
    auto [it, fresh] = index_.try_emplace(name, classes_.size());
    if (fresh) classes_.push_back(name);
    return "struct __rk_class" + std::to_string(it->second);
  }

 private:
  static std::string join(const std::string &a, const std::string &b) { return b.empty() ? a : a + " " + b; }

  // A builtin's C spelling for the target; "" when it has none.
  std::string builtin(const std::string &n) const {
    const auto &r = profile_->rules;
    auto int_of = [](std::uint32_t size, bool is_signed) -> std::string {
      switch (size) {
        case 1: return is_signed ? "signed char" : "unsigned char";
        case 2: return is_signed ? "short" : "unsigned short";
        case 4: return is_signed ? "int" : "unsigned int";
        case 8: return is_signed ? "long long" : "unsigned long long";
        default: return {};
      }
    };
    if (n == "bool") return "_Bool";
    if (n == "wchar_t") return int_of(r.wchar_size, r.wchar_signed);
    if (n == "char8_t") return "unsigned char";
    if (n == "char16_t") return "unsigned short";
    if (n == "char32_t") return "unsigned int";
    if (n == "decltype(nullptr)" || n == "std::nullptr_t") return "void *";
    if (n == "__int128" || n == "unsigned __int128") return r.has_int128 ? n : std::string();
    static constexpr std::string_view kSame[] = {"void", "char", "signed char", "unsigned char", "short",
                                                 "unsigned short", "int", "unsigned int", "long", "unsigned long",
                                                 "long long", "unsigned long long", "float", "double", "long double"};
    for (std::string_view s : kSame)
      if (n == s) return n;
    return {};
  }

  std::string write(const Type &t, const std::string &inner, bool behind_pointer) {
    const std::string q = std::string(t.is_const ? "const " : "") + (t.is_volatile ? "volatile " : "");
    switch (t.kind) {
      case Type::Kind::Builtin: {
        std::string b = builtin(t.name);
        if (b.empty() || (b == "void" && !behind_pointer)) {
          ok_ = false;
          return {};
        }
        if (b == "void *") return join(q + "void *", inner);  // nullptr_t
        return join(q + b, inner);
      }
      case Type::Kind::Enum:
        // A Microsoft enum is an int whatever its values.
        return join(q + "int", inner);
      case Type::Kind::Named:
      case Type::Kind::Record:
        if (!behind_pointer) {
          ok_ = false;
          return {};
        }
        return join(q + class_ref(t.name), inner);
      case Type::Kind::Pointer:
      case Type::Kind::Reference: {
        if (t.children.empty()) break;
        const Type &to = t.children[0];
        std::string d = "*" + std::string(t.is_const && t.kind == Type::Kind::Pointer ? "const " : "") + inner;
        if (to.kind == Type::Kind::Function || to.kind == Type::Kind::Array) d = "(" + d + ")";
        return decl(to, d, true);
      }
      case Type::Kind::Array: {
        if (t.children.empty()) break;
        const std::string d = inner + "[" + (t.count != 0 ? std::to_string(t.count) : std::string()) + "]";
        return decl(t.children[0], d, behind_pointer);
      }
      case Type::Kind::Function: {
        if (t.children.empty()) break;
        std::string params;
        for (std::size_t i = 1; i < t.children.size(); ++i) {
          if (!params.empty()) params += ", ";
          params += param(t.children[i], "");
        }
        if (t.varargs) params += params.empty() ? "..." : ", ...";
        if (params.empty()) params = "void";
        const Type &ret = t.children[0];
        // A function pointer's unknown or class return: an int, as C
        // would; anything better needs the layout.
        if (ret.kind == Type::Kind::Named || ret.kind == Type::Kind::Record || ret.kind == Type::Kind::Unknown) {
          ok_ = false;
          return {};
        }
        return decl(ret, inner + "(" + params + ")", ret.kind == Type::Kind::Builtin && ret.name == "void");
      }
      case Type::Kind::Unknown: break;
    }
    ok_ = false;
    return {};
  }

  const cparse::Profile *profile_;
  std::vector<std::string> classes_;
  std::map<std::string, std::size_t> index_;
  bool ok_ = true;
  int depth_ = 0;
};

namespace {


types::CallConv convention_of(const std::string &cc) {
  if (cc == "__cdecl") return types::CallConv::Cdecl;
  if (cc == "__stdcall") return types::CallConv::Stdcall;
  if (cc == "__fastcall") return types::CallConv::Fastcall;
  if (cc == "__thiscall") return types::CallConv::Thiscall;
  if (cc == "__vectorcall") return types::CallConv::Vectorcall;
  if (cc == "__pascal") return types::CallConv::Pascal;
  if (cc == "__regcall") return types::CallConv::Regcall;
  return types::CallConv::Default;
}

}  // namespace

std::string convention_name(types::CallConv cc) {
  switch (cc) {
    case types::CallConv::Cdecl: return "__cdecl";
    case types::CallConv::Stdcall: return "__stdcall";
    case types::CallConv::Fastcall: return "__fastcall";
    case types::CallConv::Thiscall: return "__thiscall";
    case types::CallConv::Vectorcall: return "__vectorcall";
    case types::CallConv::Pascal: return "__pascal";
    case types::CallConv::Regcall: return "__regcall";
    default: return {};
  }
}


std::optional<std::string> demangled_name(std::string_view symbol) {
  if (symbol.empty() || demangle::detect(symbol) == demangle::Scheme::None) return std::nullopt;
  std::optional<demangle::Demangled> d = demangle::parse(symbol);
  if (!d) return std::nullopt;
  return std::move(d->name);
}

std::vector<std::string> split_qualified(std::string_view name) {
  std::vector<std::string> out;
  int depth = 0;
  std::size_t start = 0;
  for (std::size_t i = 0; i < name.size(); ++i) {
    const char c = name[i];
    // "operator<", "operator()": the operator's characters aren't brackets.
    if (name.compare(i, 8, "operator") == 0 && (i == 0 || !(std::isalnum(static_cast<unsigned char>(name[i - 1])) || name[i - 1] == '_')) &&
        (i + 8 >= name.size() || !(std::isalnum(static_cast<unsigned char>(name[i + 8])) || name[i + 8] == '_'))) {
      i += 8;
      while (i < name.size() && name[i] == ' ') ++i;
      if (name.compare(i, 2, "()") == 0 || name.compare(i, 2, "[]") == 0) {
        i += 1;
        continue;
      }
      while (i < name.size() && std::string_view("<>=!+-*/%^&|~,").find(name[i]) != std::string_view::npos) ++i;
      --i;
      continue;
    }
    if (c == '<' || c == '(' || c == '{' || c == '[') ++depth;
    else if ((c == '>' || c == ')' || c == '}' || c == ']') && depth > 0) --depth;
    else if (depth == 0 && c == ':' && i + 1 < name.size() && name[i + 1] == ':') {
      out.emplace_back(name.substr(start, i - start));
      start = i + 2;
      ++i;
    }
  }
  out.emplace_back(name.substr(start));
  return out;
}

lift::NamespacePath namespace_path(const std::vector<std::string> &scope) {
  lift::NamespacePath out;
  std::string path;
  for (const std::string &part : scope) {
    path += "::" + part;
    std::uint64_t h = 0xcbf29ce484222325ULL;  // FNV-1a
    for (char c : path) {
      h ^= static_cast<unsigned char>(c);
      h *= 0x100000001b3ULL;
    }
    // Apart from debug info's function scopes (0x4000...) and Ghidra's own.
    out.emplace_back(0x2000000000000000ULL | (h & 0x0fffffffffffffffULL), part);
  }
  return out;
}

void ClassScopes::add(const demangle::Demangled &d) {
  if (d.function) {
    const demangle::FunctionSignature &f = *d.function;
    if (!f.context.empty() && f.member == demangle::Member::Yes) classes_.insert(f.context);
    return;
  }
  // "Shape::vtable", "Shape::typeinfo", "Shape::VTT", MSVC "Shape::vftable"
  static constexpr std::string_view kClassObjects[] = {"::vtable", "::VTT", "::typeinfo", "::typeinfo-name",
                                                       "::vftable", "::vbtable"};
  for (std::string_view suffix : kClassObjects)
    if (d.name.ends_with(suffix)) {
      classes_.insert(d.name.substr(0, d.name.size() - suffix.size()));
      return;
    }
}

bool ClassScopes::is_class(std::string_view scope) const {
  if (scope.empty()) return false;
  if (classes_.contains(scope)) return true;
  // A scope with template arguments is a class template's specialization
  // (a namespace can't have them).
  return scope.back() == '>';
}

bool takes_this(const demangle::FunctionSignature &f, const ClassScopes &scopes) {
  switch (f.member) {
    case demangle::Member::Yes: return true;
    case demangle::Member::No: return false;
    case demangle::Member::Unknown: break;
  }
  if (f.context == "std" || !scopes.is_class(f.context)) return false;
  // A two-operand operator in a class scope is a friend, not a member
  // (Ghidra's DemangledFunction.isThisCall).
  if (f.operator_name && f.params.size() >= 2) return false;
  return true;
}

struct DemangledPrototypes::Pending {
  std::string ret;
  std::string params;
  DemangledPrototype out;
  types::CallConv cc = types::CallConv::Default;
};

DemangledPrototypes::DemangledPrototypes(const ClassScopes &scopes, const cparse::Profile &profile,
                                         types::TypeStore &store)
    : scopes_(scopes), profile_(profile), store_(store) {}

DemangledPrototypes::~DemangledPrototypes() = default;

std::optional<std::size_t> DemangledPrototypes::add(const demangle::Demangled &d) {
  if (!d.function) return std::nullopt;
  const demangle::FunctionSignature &f = *d.function;
  // A clone's parameters may differ from the signature's (GCC drops and
  // splits them); a cold part isn't a function.
  if (!f.clone_suffix.empty()) return std::nullopt;
  if (!writer_) writer_ = std::make_unique<CWriter>(profile_);
  // Written on a copy, so a signature that can't be written leaves no
  // class behind.
  CWriter w = *writer_;
  Pending p;
  DemangledPrototype &out = p.out;
  out.has_this = takes_this(f, scopes_);
  out.this_guessed = out.has_this && f.member == demangle::Member::Unknown;
  if (out.has_this) {
    p.params = std::string(f.this_const ? "const " : "") + w.class_ref(f.context) + " *this";
    ++out.params;
  }
  for (std::size_t i = 0; i < f.params.size(); ++i) {
    if (!p.params.empty()) p.params += ", ";
    p.params += w.param(f.params[i], "param_" + std::to_string(out.params + 1));
    ++out.params;
  }
  if (!w.ok()) return std::nullopt;
  if (f.varargs) p.params += p.params.empty() ? "..." : ", ...";
  if (p.params.empty()) p.params = "void";
  p.ret = "void";
  out.unknown_return = true;
  if (f.ret && !f.constructor && !f.destructor) {
    CWriter rw = w;
    std::string r = rw.decl(*f.ret, "", f.ret->kind == Type::Kind::Builtin && f.ret->name == "void");
    if (rw.ok()) {
      w = rw;
      p.ret = r;
      out.unknown_return = false;
    }
  } else if (f.destructor) {
    // Destructors return nothing. Constructors are left to the decompiler
    // (Microsoft's and ARM's return `this`).
    out.unknown_return = false;
  }
  p.cc = convention_of(f.convention);
  *writer_ = std::move(w);
  pending_.push_back(std::move(p));
  results_.emplace_back();
  return pending_.size() - 1;
}

void DemangledPrototypes::parse() {
  if (pending_.empty()) return;
  // Classes are declared structs named as the manglings name them.
  std::vector<types::TypeId> classes;
  for (const std::string &name : writer_->classes()) {
    types::AggregateType a;
    a.kind = types::AggregateKind::Class;
    a.name = name;
    a.complete = false;
    classes.push_back(store_.intern(types::Type(a)));
  }
  cparse::Options o;
  o.profile = profile_;
  o.builtin_headers = false;
  o.limits.wall_time = std::chrono::milliseconds(60'000);
  o.limits.max_diagnostics = 100;
  o.lookup = [&](std::string_view key) -> std::optional<types::TypeId> {
    constexpr std::string_view kPrefix = "struct __rk_class";
    if (!key.starts_with(kPrefix)) return std::nullopt;
    const std::string_view n = key.substr(kPrefix.size());
    std::size_t i = 0;
    for (char c : n) {
      if (c < '0' || c > '9') return std::nullopt;
      i = i * 10 + static_cast<std::size_t>(c - '0');
    }
    if (n.empty() || i >= classes.size()) return std::nullopt;
    return classes[i];
  };
  // One translation unit for all of them: a declaration cparse can't read
  // is reported and skipped, and the others still parse.
  std::string text;
  for (std::size_t i = 0; i < pending_.size(); ++i) {
    Pending &p = pending_[i];
    p.out.c = p.ret + (p.ret.ends_with("*") ? "" : " ") + "__rk_fn" + std::to_string(i) + "(" + p.params + ");";
    text += p.out.c;
    text += '\n';
  }
  cparse::Source src{"<demangled>", std::move(text), false};
  cparse::Result r;
  try {
    r = cparse::parse(store_, std::span<const cparse::Source>(&src, 1), o);
  } catch (const std::exception &) {
    pending_.clear();
    return;
  }
  for (const cparse::Prototype &proto : r.prototypes) {
    if (!proto.name.starts_with("__rk_fn")) continue;
    const std::size_t i = std::strtoull(proto.name.c_str() + 7, nullptr, 10);
    if (i >= pending_.size()) continue;
    const auto *fn = store_.get(proto.type).as<types::FunctionType>();
    if (fn == nullptr) continue;
    types::FunctionType ft = *fn;
    ft.cc = pending_[i].cc;
    DemangledPrototype out = std::move(pending_[i].out);
    out.type = store_.function(std::move(ft));
    results_[i] = std::move(out);
  }
  pending_.clear();
}

const std::optional<DemangledPrototype> &DemangledPrototypes::get(std::size_t i) const { return results_.at(i); }

std::optional<DemangledPrototype> demangled_prototype(const demangle::Demangled &d, const ClassScopes &scopes,
                                                      const cparse::Profile &profile, types::TypeStore &store) {
  DemangledPrototypes batch(scopes, profile, store);
  std::optional<std::size_t> i = batch.add(d);
  if (!i) return std::nullopt;
  batch.parse();
  return batch.get(*i);
}

void apply_demangled(lift::FunctionFacts &f, const DemangledPrototype &p, GhidraTypes &enc,
                     const std::set<std::string> &models) {
  const auto *fn = enc.store().get(p.type).as<types::FunctionType>();
  if (fn == nullptr) return;
  f.signature_source = lift::SignatureSource::imported;
  f.demangled = true;
  const std::string cc = convention_name(fn->cc);
  f.convention = !cc.empty() && models.contains(cc) ? cc : std::string("default");
  f.dynamic_storage = true;
  f.ret = lift::FunctionFacts::Return{};
  if (p.unknown_return) {
    // Ghidra's DEFAULT "undefined" with no storage: an unlocked return the
    // decompiler decides (as a demangled C++ signature leaves it).
    f.ret.type = {"typeref", {{"id", std::uint64_t{0xc000000000000000ULL}}, {"name", std::string("undefined")}}, {}};
    f.ret.is_default = true;
    f.ret.storage = std::nullopt;
    f.ret.size = 1;
  } else {
    f.ret.type = enc.ref(fn->ret);
    f.ret.is_default = false;
  }
  f.varargs = fn->varargs;
  f.this_guessed = p.this_guessed;
  f.params.clear();
  for (std::size_t i = 0; i < fn->params.size(); ++i) {
    lift::ParamFacts param;
    param.name = fn->params[i].name.empty() ? "param_" + std::to_string(i + 1) : fn->params[i].name;
    param.type = enc.ref(fn->params[i].type);
    f.params.push_back(std::move(param));
  }
}

bool refine_demangled_this(lift::FunctionFacts &f, const std::vector<bool> &found_float) {
  if (!f.this_guessed || f.params.empty() || found_float.size() + 1 != f.params.size()) return false;
  auto is_float = [](const lift::DecompElement &t) {
    const auto *m = t.attr("metatype");
    return m != nullptr && std::holds_alternative<std::string>(*m) && std::get<std::string>(*m) == "float";
  };
  std::size_t mangled_float = 0, found = 0;
  for (std::size_t i = 1; i < f.params.size(); ++i) mangled_float += is_float(f.params[i].type);
  for (bool b : found_float) found += b;
  if (found != mangled_float) return false;
  f.params.erase(f.params.begin());
  for (std::size_t i = 0; i < f.params.size(); ++i)
    if (f.params[i].name.starts_with("param_")) f.params[i].name = "param_" + std::to_string(i + 1);
  f.this_guessed = false;
  return true;
}

std::string demangled_display(const DemangledPrototype &p, const types::TypeStore &store, std::string_view name) {
  std::string s = types::prototype(store, p.type, name);
  if (p.unknown_return && s.starts_with("void ")) s = "undefined " + s.substr(5);
  // Classes by their names, as C++ (and Ghidra's listing) spell them.
  std::string out;
  out.reserve(s.size());
  for (std::size_t i = 0; i < s.size(); ++i) {
    if (s.compare(i, 6, "class ") == 0 && (i == 0 || s[i - 1] == ' ' || s[i - 1] == '(' || s[i - 1] == ',')) {
      i += 5;
      continue;
    }
    out += s[i];
  }
  return out;
}

}  // namespace revkit::inputs
