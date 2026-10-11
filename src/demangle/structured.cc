// Structured demangling: the demangler analysis's names and the parts of a
// function's mangled signature (docs/demangle.md), from LLVM's demangler
// ASTs (Itanium: llvm::itanium_demangle; Microsoft: llvm::ms_demangle).

#include "revkit/demangle/demangle.h"

#include "llvm/Demangle/Demangle.h"
#include "llvm/Demangle/ItaniumDemangle.h"
#include "llvm/Demangle/MicrosoftDemangle.h"
#include "llvm/Demangle/MicrosoftDemangleNodes.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <memory>
#include <type_traits>
#include <vector>

#if __has_include(<cxxabi.h>)
#include <cxxabi.h>
#define REVKIT_HAVE_CXXABI 1
#endif

namespace revkit::demangle {
namespace {

namespace it = llvm::itanium_demangle;

// The Itanium parser's node allocator: nodes live until the parse's
// result has been read, and are never destroyed one by one.
class Arena {
 public:
  void reset() { blocks_.clear(); used_ = kBlock; }
  template <typename T, typename... Args>
  T *makeNode(Args &&...args) {
    return new (allocate(sizeof(T))) T(std::forward<Args>(args)...);
  }
  void *allocateNodeArray(std::size_t n) { return allocate(sizeof(it::Node *) * n); }

 private:
  static constexpr std::size_t kBlock = 4096;
  void *allocate(std::size_t n) {
    n = (n + 15) & ~std::size_t{15};
    if (n > kBlock) {
      blocks_.push_back(std::make_unique<std::byte[]>(n));
      return blocks_.back().get();
    }
    if (used_ + n > kBlock) {
      blocks_.push_back(std::make_unique<std::byte[]>(kBlock));
      used_ = 0;
    }
    void *p = blocks_.back().get() + used_;
    used_ += n;
    return p;
  }
  std::vector<std::unique_ptr<std::byte[]>> blocks_;
  std::size_t used_ = kBlock;
};

using Parser = it::ManglingParser<Arena>;

std::string print(const it::Node *n) {
  if (n == nullptr) return {};
  it::OutputBuffer ob;
  n->print(ob);
  std::string out(ob.getBuffer() != nullptr ? std::string_view(ob.getBuffer(), ob.getCurrentPosition()) : std::string_view());
  std::free(ob.getBuffer());
  return out;
}

std::string print_ms(const llvm::ms_demangle::Node *n, llvm::ms_demangle::OutputFlags flags = llvm::ms_demangle::OF_Default) {
  if (n == nullptr) return {};
  return n->toString(flags);
}

// A name as the analysis keeps it, one token wherever it is printed: no
// space after a template argument's comma, other spaces as '_' (as
// Ghidra's SymbolUtilities.replaceInvalidChars makes them):
// "std::map<int, unsigned int>" -> "std::map<int,unsigned_int>".
std::string normalize(std::string_view in) {
  std::string out;
  out.reserve(in.size());
  for (std::size_t i = 0; i < in.size(); ++i) {
    const char c = in[i];
    if (c == ' ') {
      if (!out.empty() && out.back() == ',') continue;
      out += '_';
    } else {
      out += c;
    }
  }
  return out;
}

void normalize_type(Type &t) {
  if (t.kind == Type::Kind::Named || t.kind == Type::Kind::Record || t.kind == Type::Kind::Enum) t.name = normalize(t.name);
  for (Type &c : t.children) normalize_type(c);
}

bool builtin_spelling(std::string_view s) {
  static constexpr std::string_view kBuiltins[] = {
      "void", "bool", "char", "signed char", "unsigned char", "wchar_t", "char8_t", "char16_t", "char32_t",
      "short", "unsigned short", "int", "unsigned int", "long", "unsigned long", "long long",
      "unsigned long long", "__int128", "unsigned __int128", "float", "double", "long double", "__float128",
      "decltype(nullptr)", "std::nullptr_t"};
  return std::find(std::begin(kBuiltins), std::end(kBuiltins), s) != std::end(kBuiltins);
}

// --- Itanium ---------------------------------------------------------------

struct ItaniumTypes {
  int depth = 0;

  Type unknown(const it::Node *n) {
    Type t;
    t.kind = Type::Kind::Unknown;
    t.name = print(n);
    return t;
  }

  Type named(const it::Node *n) {
    Type t;
    t.name = print(n);
    t.kind = builtin_spelling(t.name) || t.name == "..." ? Type::Kind::Builtin : Type::Kind::Named;
    return t;
  }

  Type of(const it::Node *n) {
    if (n == nullptr) return unknown(n);
    if (++depth > 64) {
      --depth;
      return unknown(n);
    }
    Type out = convert(n);
    --depth;
    return out;
  }

  Type convert(const it::Node *n) {
    Type out;
    bool done = false;
    n->visit([&](const auto *node) {
      using T = std::remove_cv_t<std::remove_pointer_t<decltype(node)>>;
      if constexpr (std::is_same_v<T, it::NameType>) {
        out = named(node);
        done = true;
      } else if constexpr (std::is_same_v<T, it::NestedName> || std::is_same_v<T, it::NameWithTemplateArgs> ||
                           std::is_same_v<T, it::GlobalQualifiedName> || std::is_same_v<T, it::LocalName> ||
                           std::is_same_v<T, it::ExpandedSpecialSubstitution> ||
                           std::is_same_v<T, it::SpecialSubstitution> || std::is_same_v<T, it::AbiTagAttr> ||
                           std::is_same_v<T, it::ModuleEntity>) {
        out = named(node);
        done = true;
      } else if constexpr (std::is_same_v<T, it::ElaboratedTypeSpefType>) {
        node->match([&](std::string_view, const it::Node *child) { out = of(child); });
        done = true;
      } else if constexpr (std::is_same_v<T, it::QualType>) {
        out = of(node->getChild());
        out.is_const = out.is_const || (node->getQuals() & it::QualConst) != 0;
        out.is_volatile = out.is_volatile || (node->getQuals() & it::QualVolatile) != 0;
        done = true;
      } else if constexpr (std::is_same_v<T, it::VendorExtQualType>) {
        out = of(node->getTy());  // __restrict, address spaces: dropped
        done = true;
      } else if constexpr (std::is_same_v<T, it::PointerType>) {
        out.kind = Type::Kind::Pointer;
        out.children.push_back(of(node->getPointee()));
        done = true;
      } else if constexpr (std::is_same_v<T, it::ReferenceType>) {
        node->match([&](const it::Node *pointee, it::ReferenceKind) {
          out.kind = Type::Kind::Reference;
          out.children.push_back(of(pointee));
        });
        done = true;
      } else if constexpr (std::is_same_v<T, it::ArrayType>) {
        node->match([&](const it::Node *base, const it::Node *dim) {
          out.kind = Type::Kind::Array;
          out.children.push_back(of(base));
          const std::string d = print(dim);
          char *end = nullptr;
          const unsigned long long v = d.empty() ? 0 : std::strtoull(d.c_str(), &end, 10);
          out.count = end != nullptr && *end == '\0' ? v : 0;
        });
        done = true;
      } else if constexpr (std::is_same_v<T, it::FunctionType>) {
        node->match([&](const it::Node *ret, it::NodeArray params, it::Qualifiers, it::FunctionRefQual, const it::Node *) {
          out.kind = Type::Kind::Function;
          out.children.push_back(of(ret));
          for (const it::Node *p : params) {
            Type t = of(p);
            if (t.kind == Type::Kind::Builtin && t.name == "...") {
              out.varargs = true;
              continue;
            }
            out.children.push_back(std::move(t));
          }
        });
        done = true;
      } else if constexpr (std::is_same_v<T, it::ForwardTemplateReference>) {
        if (node->Ref != nullptr && !node->Printing) {
          node->Printing = true;
          out = of(node->Ref);
          node->Printing = false;
          done = true;
        }
      }
    });
    if (!done) {
      out = unknown(n);
      // "..." (a C variadic parameter) is a NameType; anything else unknown.
    }
    return out;
  }
};

// A name as the analysis spells it: a local entity's enclosing function
// by its name alone ("f::{lambda()#1}", not "f(int)::{lambda()#1}"), and
// no ABI tags ("describe", not "describe[abi:cxx11]").
std::string name_text(const it::Node *n, int depth = 0) {
  if (n == nullptr) return {};
  if (depth > 32) return print(n);
  switch (n->getKind()) {
    case it::Node::KAbiTagAttr: return name_text(static_cast<const it::AbiTagAttr *>(n)->Base, depth + 1);
    case it::Node::KNestedName: {
      const auto *nn = static_cast<const it::NestedName *>(n);
      return name_text(nn->Qual, depth + 1) + "::" + name_text(nn->Name, depth + 1);
    }
    case it::Node::KLocalName: {
      const auto *ln = static_cast<const it::LocalName *>(n);
      const it::Node *enc = ln->Encoding;
      if (enc != nullptr && enc->getKind() == it::Node::KFunctionEncoding)
        enc = static_cast<const it::FunctionEncoding *>(enc)->getName();
      return name_text(enc, depth + 1) + "::" + name_text(ln->Entity, depth + 1);
    }
    case it::Node::KNameWithTemplateArgs: {
      const auto *nt = static_cast<const it::NameWithTemplateArgs *>(n);
      return name_text(nt->Name, depth + 1) + print(nt->TemplateArgs);
    }
    default: return print(n);
  }
}

const it::Node *strip_abi(const it::Node *name) {
  while (name != nullptr && name->getKind() == it::Node::KAbiTagAttr) name = static_cast<const it::AbiTagAttr *>(name)->Base;
  return name;
}

// A SpecialName's prefix ("vtable for ") as the analysis's suffix
// ("::vtable"), as Ghidra's demangler names them.
std::string special_name(std::string_view special, const std::string &child) {
  static constexpr std::pair<std::string_view, std::string_view> kSpecial[] = {
      {"vtable for ", "vtable"},
      {"VTT for ", "VTT"},
      {"typeinfo for ", "typeinfo"},
      {"typeinfo name for ", "typeinfo-name"},
      {"guard variable for ", "guard"},
      {"reference temporary for ", "reference-temporary"},
      {"TLS init function for ", "tls-init"},
      {"TLS wrapper function for ", "tls-wrapper"},
      {"hidden alias for ", "hidden-alias"},
      {"transaction clone for ", "transaction-clone"},
  };
  for (const auto &[prefix, suffix] : kSpecial)
    if (special == prefix) return child + "::" + std::string(suffix);
  return std::string(special) + child;
}

std::optional<Demangled> parse_itanium(std::string_view symbol) {
  std::string owned(symbol);
  std::string_view s = owned;
  for (int i = 0; i < 2 && s.starts_with("__Z"); ++i)
    if (!s.starts_with("___Z")) s.remove_prefix(1);
  if (s.starts_with("___Z")) s.remove_prefix(2);  // block invocations: _Z...
  Parser parser(s.data(), s.data() + s.size());
  const it::Node *root = parser.parse();
  if (root == nullptr) {
    // _GLOBAL__sub_I_<file> and friends aren't mangled names LLVM parses.
    return std::nullopt;
  }
  Demangled d;
  d.scheme = Scheme::Itanium;
  d.full = print(root);
  std::string clone;
  if (root->getKind() == it::Node::KDotSuffix) {
    root->visit([&](const auto *node) {
      using T = std::remove_cv_t<std::remove_pointer_t<decltype(node)>>;
      if constexpr (std::is_same_v<T, it::DotSuffix>) {
        node->match([&](const it::Node *prefix, std::string_view suffix) {
          root = prefix;
          clone = std::string(suffix);
        });
      }
    });
    // "(.isra.0)" -> ".isra.0"
    std::erase_if(clone, [](char c) { return c == '(' || c == ')' || c == ' '; });
  }
  if (root->getKind() == it::Node::KSpecialName) {
    root->visit([&](const auto *node) {
      using T = std::remove_cv_t<std::remove_pointer_t<decltype(node)>>;
      if constexpr (std::is_same_v<T, it::SpecialName>) {
        node->match([&](std::string_view special, const it::Node *child) {
          // A thunk names the function it adjusts for.
          if (special.find("thunk to ") != std::string_view::npos && child != nullptr &&
              child->getKind() == it::Node::KFunctionEncoding) {
            d.name = name_text(static_cast<const it::FunctionEncoding *>(child)->getName());
            return;
          }
          d.name = special_name(special, name_text(child));
        });
      }
    });
    if (d.name.empty()) d.name = d.full;
    return d;
  }
  if (root->getKind() != it::Node::KFunctionEncoding) {
    // A variable or other entity: its qualified name.
    d.name = name_text(root) + clone;
    return d;
  }
  const auto *enc = static_cast<const it::FunctionEncoding *>(root);
  d.name = name_text(enc->getName()) + clone;
  FunctionSignature f;
  f.clone_suffix = clone;
  // The scope and the base name, as ItaniumPartialDemangler finds them.
  const it::Node *name = strip_abi(enc->getName());
  bool local = false;
  while (true) {
    name = strip_abi(name);
    if (name->getKind() == it::Node::KNameWithTemplateArgs) {
      name = static_cast<const it::NameWithTemplateArgs *>(name)->Name;
      continue;
    }
    if (name->getKind() == it::Node::KModuleEntity) {
      name = static_cast<const it::ModuleEntity *>(name)->Name;
      continue;
    }
    if (name->getKind() == it::Node::KNestedName) {
      const auto *nn = static_cast<const it::NestedName *>(name);
      f.context = (f.context.empty() ? std::string() : f.context + "::") + name_text(nn->Qual);
      name = nn->Name;
      continue;
    }
    if (name->getKind() == it::Node::KLocalName) {
      const auto *ln = static_cast<const it::LocalName *>(name);
      const it::Node *enc_name = ln->Encoding;
      if (enc_name != nullptr && enc_name->getKind() == it::Node::KFunctionEncoding)
        enc_name = static_cast<const it::FunctionEncoding *>(enc_name)->getName();
      f.context = (f.context.empty() ? std::string() : f.context + "::") + name_text(enc_name);
      name = ln->Entity;
      local = true;
      continue;
    }
    break;
  }
  name = strip_abi(name);
  if (name->getKind() == it::Node::KNameWithTemplateArgs) name = static_cast<const it::NameWithTemplateArgs *>(name)->Name;
  f.base_name = name_text(name);
  if (name->getKind() == it::Node::KCtorDtorName) {
    name->visit([&](const auto *node) {
      using T = std::remove_cv_t<std::remove_pointer_t<decltype(node)>>;
      if constexpr (std::is_same_v<T, it::CtorDtorName>) {
        node->match([&](const it::Node *, bool dtor, int) {
          f.destructor = dtor;
          f.constructor = !dtor;
        });
      }
    });
  }
  f.operator_name = f.base_name.starts_with("operator") &&
                    (f.base_name.size() == 8 || !(std::isalnum(static_cast<unsigned char>(f.base_name[8])) || f.base_name[8] == '_'));
  f.this_const = (enc->getCVQuals() & it::QualConst) != 0;
  if (f.constructor || f.destructor || enc->getCVQuals() != it::QualNone || enc->getRefQual() != it::FrefQualNone)
    f.member = Member::Yes;
  else if (f.context.empty())
    f.member = Member::No;
  (void)local;
  ItaniumTypes types;
  if (enc->getReturnType() != nullptr) f.ret = types.of(enc->getReturnType());
  for (const it::Node *p : enc->getParams()) {
    Type t = types.of(p);
    if (t.kind == Type::Kind::Builtin && t.name == "...") {
      f.varargs = true;
      continue;
    }
    // A pack expanded to nothing, or "void" alone, is no parameter.
    if (t.kind == Type::Kind::Builtin && t.name == "void" && enc->getParams().size() == 1) continue;
    f.params.push_back(std::move(t));
  }
  d.function = std::move(f);
  return d;
}

// --- Microsoft ---------------------------------------------------------------

namespace ms = llvm::ms_demangle;

struct MsTypes {
  int depth = 0;

  static std::string prim(ms::PrimitiveKind k) {
    switch (k) {
      case ms::PrimitiveKind::Void: return "void";
      case ms::PrimitiveKind::Bool: return "bool";
      case ms::PrimitiveKind::Char: return "char";
      case ms::PrimitiveKind::Schar: return "signed char";
      case ms::PrimitiveKind::Uchar: return "unsigned char";
      case ms::PrimitiveKind::Char8: return "char8_t";
      case ms::PrimitiveKind::Char16: return "char16_t";
      case ms::PrimitiveKind::Char32: return "char32_t";
      case ms::PrimitiveKind::Short: return "short";
      case ms::PrimitiveKind::Ushort: return "unsigned short";
      case ms::PrimitiveKind::Int: return "int";
      case ms::PrimitiveKind::Uint: return "unsigned int";
      case ms::PrimitiveKind::Long: return "long";
      case ms::PrimitiveKind::Ulong: return "unsigned long";
      case ms::PrimitiveKind::Int64: return "long long";
      case ms::PrimitiveKind::Uint64: return "unsigned long long";
      case ms::PrimitiveKind::Wchar: return "wchar_t";
      case ms::PrimitiveKind::Float: return "float";
      case ms::PrimitiveKind::Double: return "double";
      case ms::PrimitiveKind::Ldouble: return "long double";
      case ms::PrimitiveKind::Nullptr: return "std::nullptr_t";
      default: return {};
    }
  }

  Type of(const ms::Node *n) {
    Type out;
    if (n == nullptr || ++depth > 64) {
      if (n != nullptr) --depth;
      out.kind = Type::Kind::Unknown;
      return out;
    }
    out = convert(n);
    --depth;
    return out;
  }

  Type convert(const ms::Node *n) {
    Type out;
    out.kind = Type::Kind::Unknown;
    out.name = print_ms(n);
    const auto *tn = ms::TypeNode::classof(n) ? static_cast<const ms::TypeNode *>(n) : nullptr;
    switch (n->kind()) {
      case ms::NodeKind::PrimitiveType: {
        const std::string p = prim(static_cast<const ms::PrimitiveTypeNode *>(n)->PrimKind);
        if (!p.empty()) {
          out.kind = Type::Kind::Builtin;
          out.name = p;
        }
        break;
      }
      case ms::NodeKind::TagType: {
        const auto *t = static_cast<const ms::TagTypeNode *>(n);
        out.kind = t->Tag == ms::TagKind::Enum ? Type::Kind::Enum : Type::Kind::Record;
        out.name = print_ms(t->QualifiedName);
        break;
      }
      case ms::NodeKind::PointerType: {
        const auto *p = static_cast<const ms::PointerTypeNode *>(n);
        if (p->ClassParent != nullptr) break;  // a member pointer
        out.name.clear();
        out.kind = p->Affinity == ms::PointerAffinity::Pointer ? Type::Kind::Pointer : Type::Kind::Reference;
        out.children.push_back(of(p->Pointee));
        break;
      }
      case ms::NodeKind::ArrayType: {
        const auto *a = static_cast<const ms::ArrayTypeNode *>(n);
        if (a->Dimensions == nullptr || a->Dimensions->Count == 0) break;
        // [3][4]: an array of 3 arrays of 4.
        Type elem = of(a->ElementType);
        for (std::size_t i = a->Dimensions->Count; i-- > 0;) {
          Type arr;
          arr.kind = Type::Kind::Array;
          const ms::Node *dim = a->Dimensions->Nodes[i];
          if (dim != nullptr && dim->kind() == ms::NodeKind::IntegerLiteral)
            arr.count = static_cast<const ms::IntegerLiteralNode *>(dim)->Value;
          arr.children.push_back(std::move(elem));
          elem = std::move(arr);
        }
        out = std::move(elem);
        break;
      }
      case ms::NodeKind::FunctionSignature: {
        const auto *f = static_cast<const ms::FunctionSignatureNode *>(n);
        out.name.clear();
        out.kind = Type::Kind::Function;
        out.children.push_back(of(f->ReturnType));
        if (f->Params != nullptr)
          for (std::size_t i = 0; i < f->Params->Count; ++i) out.children.push_back(of(f->Params->Nodes[i]));
        out.varargs = f->IsVariadic;
        break;
      }
      default: break;
    }
    if (tn != nullptr) {
      out.is_const = out.is_const || (tn->Quals & ms::Q_Const) != 0;
      out.is_volatile = out.is_volatile || (tn->Quals & ms::Q_Volatile) != 0;
    }
    return out;
  }
};

std::string convention(ms::CallingConv cc) {
  switch (cc) {
    case ms::CallingConv::Cdecl: return "__cdecl";
    case ms::CallingConv::Stdcall: return "__stdcall";
    case ms::CallingConv::Fastcall: return "__fastcall";
    case ms::CallingConv::Thiscall: return "__thiscall";
    case ms::CallingConv::Vectorcall: return "__vectorcall";
    case ms::CallingConv::Pascal: return "__pascal";
    case ms::CallingConv::Clrcall: return "__clrcall";
    case ms::CallingConv::Regcall: return "__regcall";
    default: return {};
  }
}

std::optional<Demangled> parse_microsoft(std::string_view symbol) {
  std::string owned(symbol);
  std::string_view s = owned;
  if (s.starts_with("__imp_")) s.remove_prefix(6);
  ms::Demangler dem;
  ms::SymbolNode *root = dem.parse(s);
  if (dem.Error || root == nullptr) return std::nullopt;
  Demangled d;
  d.scheme = Scheme::Microsoft;
  d.full = print_ms(root);
  d.name = root->Name != nullptr ? print_ms(root->Name) : d.full;
  if (root->kind() == ms::NodeKind::SpecialTableSymbol) {
    // "const Shape::`vftable'" -> "Shape::vftable"
    std::string n = d.name;
    std::erase_if(n, [](char c) { return c == '`' || c == '\''; });
    d.name = n;
    return d;
  }
  if (root->kind() != ms::NodeKind::FunctionSymbol) return d;
  const auto *fs = static_cast<const ms::FunctionSymbolNode *>(root);
  const ms::FunctionSignatureNode *sig = fs->Signature;
  if (sig == nullptr) return d;
  FunctionSignature f;
  if (root->Name != nullptr && root->Name->Components != nullptr && root->Name->Components->Count > 0) {
    const std::size_t n = root->Name->Components->Count;
    for (std::size_t i = 0; i + 1 < n; ++i) {
      if (!f.context.empty()) f.context += "::";
      f.context += print_ms(root->Name->Components->Nodes[i]);
    }
    const ms::Node *last = root->Name->Components->Nodes[n - 1];
    f.base_name = print_ms(last);
    if (last->kind() == ms::NodeKind::StructorIdentifier) {
      const auto *si = static_cast<const ms::StructorIdentifierNode *>(last);
      f.destructor = si->IsDestructor;
      f.constructor = !si->IsDestructor;
    }
    f.operator_name = last->kind() == ms::NodeKind::IntrinsicFunctionIdentifier ||
                      last->kind() == ms::NodeKind::ConversionOperatorIdentifier;
  }
  const bool global = (sig->FunctionClass & ms::FC_Global) != 0;
  const bool stat = (sig->FunctionClass & ms::FC_Static) != 0;
  f.member = global || stat || f.context.empty() ? Member::No : Member::Yes;
  if (sig->FunctionClass & ms::FC_NoParameterList) return d;
  f.this_const = (sig->Quals & ms::Q_Const) != 0;
  f.convention = convention(sig->CallConvention);
  MsTypes types;
  // Constructors and destructors have no return type in the mangling.
  if (sig->ReturnType != nullptr) f.ret = types.of(sig->ReturnType);
  if (sig->Params != nullptr)
    for (std::size_t i = 0; i < sig->Params->Count; ++i) {
      Type t = types.of(sig->Params->Nodes[i]);
      if (t.kind == Type::Kind::Builtin && t.name == "void" && sig->Params->Count == 1) continue;
      f.params.push_back(std::move(t));
    }
  f.varargs = sig->IsVariadic;
  d.function = std::move(f);
  return d;
}

// What LLVM's Itanium demangler can't parse (some template expressions,
// e.g. libstdc++'s __relocate_a_1), the C++ runtime's demangler may (GNU
// libiberty's, in libstdc++): its output's name, without the return type
// and parameter list.
std::optional<Demangled> parse_runtime(std::string_view symbol) {
#ifdef REVKIT_HAVE_CXXABI
  std::string owned(symbol);
  int status = 0;
  std::unique_ptr<char, decltype(&std::free)> out(abi::__cxa_demangle(owned.c_str(), nullptr, nullptr, &status), &std::free);
  if (status != 0 || !out) return std::nullopt;
  Demangled d;
  d.scheme = Scheme::Itanium;
  d.full = out.get();
  std::string_view s = d.full;
  // The parameter list: the last top-level "(...)".
  std::size_t open = std::string_view::npos;
  int depth = 0;
  for (std::size_t i = 0; i < s.size(); ++i) {
    const char c = s[i];
    if (c == '<') ++depth;
    else if (c == '>') --depth;
    else if (c == '(' && depth == 0 && i > 0 && s[i - 1] != ' ') {
      open = i;
      break;
    }
  }
  std::string_view name = open == std::string_view::npos ? s : s.substr(0, open);
  // Past a template's return type: the last top-level space.
  depth = 0;
  for (std::size_t i = name.size(); i-- > 0;) {
    const char c = name[i];
    if (c == '>' || c == ')') ++depth;
    else if (c == '<' || c == '(') --depth;
    else if (c == ' ' && depth == 0 && !name.substr(0, i).ends_with("operator")) {
      name = name.substr(i + 1);
      break;
    }
  }
  d.name = std::string(name);
  return d;
#else
  (void)symbol;
  return std::nullopt;
#endif
}

std::optional<Demangled> parse_other(std::string_view symbol, Scheme scheme) {
  std::optional<std::string> full = demangle(symbol);
  if (!full) return std::nullopt;
  Demangled d;
  d.scheme = scheme;
  d.full = *full;
  d.name = *full;
  return d;
}

}  // namespace

std::optional<Demangled> parse(std::string_view symbol) {
  std::optional<Demangled> d;
  switch (detect(symbol)) {
    case Scheme::Itanium:
      d = parse_itanium(symbol);
      if (!d) d = parse_runtime(symbol);
      if (!d) d = parse_other(symbol, Scheme::Itanium);
      break;
    case Scheme::Microsoft: d = parse_microsoft(symbol); break;
    case Scheme::Rust: d = parse_other(symbol, Scheme::Rust); break;
    case Scheme::D: d = parse_other(symbol, Scheme::D); break;
    case Scheme::None: break;
  }
  if (!d || d->name.empty()) return std::nullopt;
  d->name = normalize(d->name);
  if (d->function) {
    FunctionSignature &f = *d->function;
    f.context = normalize(f.context);
    f.base_name = normalize(f.base_name);
    if (f.ret) normalize_type(*f.ret);
    for (Type &t : f.params) normalize_type(t);
  }
  return d;
}

}  // namespace revkit::demangle
