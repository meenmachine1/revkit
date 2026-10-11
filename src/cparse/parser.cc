#include "parser.h"

#include "literal.h"

#include "revkit/types/packing.h"

#include <algorithm>
#include <cstdlib>
#include <functional>
#include <limits>

namespace revkit::cparse::detail {

using namespace revkit::types;

namespace {

std::uint64_t align_up(std::uint64_t v, std::uint64_t a) { return a <= 1 ? v : (v + a - 1) / a * a; }

std::string strip_underscores(std::string a) {
  if (a.size() > 4 && a.starts_with("__") && a.ends_with("__")) a = a.substr(2, a.size() - 4);
  return a;
}

std::optional<CallConv> conv_keyword(const std::string &w) {
  std::string k = w;
  while (k.starts_with("_")) k.erase(0, 1);
  while (k.ends_with("_")) k.pop_back();
  if (k == "cdecl") return CallConv::Cdecl;
  if (k == "stdcall") return CallConv::Stdcall;
  if (k == "fastcall") return CallConv::Fastcall;
  if (k == "thiscall") return CallConv::Thiscall;
  if (k == "vectorcall") return CallConv::Vectorcall;
  if (k == "pascal") return CallConv::Pascal;
  if (k == "regcall") return CallConv::Regcall;
  if (k == "ms_abi") return CallConv::Ms64;
  if (k == "sysv_abi") return CallConv::SysV;
  return std::nullopt;
}

bool is_cc_keyword(const std::string &w) {
  return w == "__cdecl" || w == "_cdecl" || w == "__stdcall" || w == "_stdcall" || w == "__fastcall" ||
         w == "_fastcall" || w == "__thiscall" || w == "__vectorcall" || w == "__pascal" || w == "__regcall" ||
         w == "__clrcall" || w == "WINAPI_UNUSED";
}

bool is_ignored_qualifier(const std::string &w) {
  return w == "__ptr64" || w == "__ptr32" || w == "__unaligned" || w == "__w64" || w == "__sptr" || w == "__uptr" ||
         w == "__extension__" || w == "_Nonnull" || w == "_Nullable" || w == "_Null_unspecified" ||
         w == "__nonnull" || w == "__nullable";
}

}  // namespace

void Attrs::merge(const Attrs &o) {
  aligned = std::max(aligned, o.aligned);
  packed = packed || o.packed;
  if (o.mode) mode = o.mode;
  if (o.vector_size) vector_size = o.vector_size;
  if (o.cc) cc = o.cc;
  if (!o.asm_label.empty()) asm_label = o.asm_label;
  noreturn = noreturn || o.noreturn;
}

Parser::Parser(Context &ctx, Preprocessor &pp, TypeStore &store)
    : ctx_(ctx), pp_(pp), store_(store), rules_(ctx.options.profile.rules) {
  cpp_ = ctx.options.cplusplus;
}

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------

const Token &Parser::peek(std::size_t n) {
  while (la_.size() <= n) {
    Token t;
    if (replay_) {
      if (replay_pos_ < replay_->size()) {
        t = (*replay_)[replay_pos_++];
      } else {
        t = eof_;
        t.kind = TK::Eof;
      }
    } else {
      t = pp_.next();
      ctx_.add_token();
      cpp_ = ctx_.options.cplusplus || pp_.cplusplus_active();
    }
    if (t.kind == TK::Pragma) {
      apply_pragma(t);
      continue;
    }
    if (t.kind == TK::Eof) {
      t.file = last_.file;
      t.line = last_.line;
      t.col = last_.col;
      t.text.clear();
    }
    la_.push_back(std::move(t));
  }
  return la_[n];
}

Token Parser::next() {
  peek();
  Token t = std::move(la_.front());
  la_.pop_front();
  if (t.kind != TK::Eof) last_ = t;
  return t;
}

bool Parser::accept(std::string_view p) {
  if (!peek().is(p)) return false;
  next();
  return true;
}

void Parser::expect(std::string_view p) {
  if (!accept(p)) {
    const Token &t = peek();
    fail(t, "expected '" + std::string(p) + "'" +
                (t.kind == TK::Eof ? std::string(" at end of input") : " before '" + t.text + "'"));
  }
}

void Parser::fail(const Token &at, std::string message) { throw ParseError{at, std::move(message)}; }

void Parser::apply_pragma(const Token &t) {
  // pack(), pack(N), pack(push[, id][, N]), pack(pop[, id | N]), pack(show)
  std::vector<std::string> args;
  {
    std::string cur;
    for (char c : t.extra) {
      if (c == ',') {
        args.push_back(cur);
        cur.clear();
      } else if (c != ' ') {
        cur += c;
      }
    }
    if (!cur.empty() || !args.empty()) args.push_back(cur);
  }
  auto num = [&](const std::string &s) -> std::optional<std::uint32_t> {
    IntLiteral l = parse_int_literal(s);
    if (!l.ok || l.is_float || l.value == 0 || l.value > 64 || (l.value & (l.value - 1))) return std::nullopt;
    return static_cast<std::uint32_t>(l.value);
  };
  if (args.empty()) {
    pack_ = 0;
    return;
  }
  if (args[0] == "push") {
    if (pack_stack_.size() < 4096) pack_stack_.push_back(pack_);
    for (std::size_t i = 1; i < args.size(); ++i)
      if (auto n = num(args[i])) pack_ = *n;
    return;
  }
  if (args[0] == "pop") {
    if (!pack_stack_.empty()) {
      pack_ = pack_stack_.back();
      pack_stack_.pop_back();
    }
    for (std::size_t i = 1; i < args.size(); ++i)
      if (auto n = num(args[i])) pack_ = *n;
    return;
  }
  if (args[0] == "show") return;
  if (auto n = num(args[0])) {
    pack_ = *n;
    return;
  }
  ctx_.warning(t, "ignoring #pragma pack(" + t.extra + ")");
}

void Parser::skip_balanced() {
  std::vector<char> stack;
  do {
    Token t = next();
    if (t.kind == TK::Eof) return;
    if (t.punct("(")) stack.push_back(')');
    else if (t.punct("[")) stack.push_back(']');
    else if (t.punct("{")) stack.push_back('}');
    else if (t.kind == TK::Punct && t.text.size() == 1 && (t.text[0] == ')' || t.text[0] == ']' || t.text[0] == '}')) {
      // Close until the matching opener (tolerating a mismatch).
      while (!stack.empty() && stack.back() != t.text[0]) stack.pop_back();
      if (!stack.empty()) stack.pop_back();
    }
  } while (!stack.empty());
}

void Parser::skip_initializer() {
  for (;;) {
    const Token &t = peek();
    if (t.kind == TK::Eof || t.punct(",") || t.punct(";") || t.punct(")") || t.punct("}")) return;
    if (t.punct("(") || t.punct("[") || t.punct("{")) skip_balanced();
    else next();
  }
}

void Parser::skip_to_semicolon() {
  for (;;) {
    const Token &t = peek();
    if (t.kind == TK::Eof) return;
    if (t.punct(";")) {
      next();
      return;
    }
    if (t.punct("{")) {
      skip_balanced();
      if (peek().punct(";")) next();
      return;
    }
    if (t.punct("(") || t.punct("[")) skip_balanced();
    else next();
  }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

TypeId Parser::add(Type t) {
  bool all_store = true;
  for_each_ref(t, [&](TypeId &r, EdgeKind) {
    if (r.is_local()) all_store = false;
  });
  if (all_store) return store_.intern(std::move(t));
  if (g_.size() >= ctx_.options.limits.max_types) throw LimitReached{"more than " + std::to_string(ctx_.options.limits.max_types) + " types"};
  return g_.add(std::move(t));
}

// The node, or nullptr. The pointer is good only until the next type is
// added (graph and store both grow by appending).
const Type *Parser::peek_type(TypeId id) const {
  if (!id.valid()) return nullptr;
  if (id.is_local()) {
    if (id.index() >= g_.size() || !g_.is_set(id)) return nullptr;
    return &g_.at(id);
  }
  if (id.index() >= store_.size()) return nullptr;
  return &store_.get(id);
}

Type Parser::get(TypeId id) const {
  const Type *t = peek_type(id);
  return t ? *t : Type(UndefinedType{1});
}

std::uint64_t Parser::size_of(TypeId id, int depth) const {
  if (depth > 64) return 0;
  const Type *t = peek_type(id);
  if (!t) return 0;
  return std::visit(
      [&](const auto &d) -> std::uint64_t {
        using D = std::decay_t<decltype(d)>;
        if constexpr (std::is_same_v<D, BoolType> || std::is_same_v<D, IntType> || std::is_same_v<D, FloatType> ||
                      std::is_same_v<D, PointerType> || std::is_same_v<D, EnumType> ||
                      std::is_same_v<D, UndefinedType>)
          return d.size;
        else if constexpr (std::is_same_v<D, ArrayType>) {
          std::uint64_t e = size_of(d.element, depth + 1);
          if (d.count && e > std::numeric_limits<std::uint64_t>::max() / d.count) return 0;
          return e * d.count;
        } else if constexpr (std::is_same_v<D, AggregateType>)
          return d.size;
        else if constexpr (std::is_same_v<D, TypedefType> || std::is_same_v<D, QualifiedType>)
          return size_of(d.target, depth + 1);
        else
          return 0;
      },
      t->data);
}

std::uint32_t Parser::align_of(TypeId id, int depth) const {
  if (depth > 64) return 1;
  const Type *t = peek_type(id);
  if (!t) return 1;
  std::uint32_t a = std::visit(
      [&](const auto &d) -> std::uint32_t {
        using D = std::decay_t<decltype(d)>;
        if constexpr (std::is_same_v<D, FloatType>) {
          if (d.kind == FloatKind::LongDouble && !d.complex) return rules_.long_double_align;
          return rules_.scalar_align(d.complex ? d.size / 2 : d.size);
        } else if constexpr (std::is_same_v<D, BoolType> || std::is_same_v<D, IntType> ||
                             std::is_same_v<D, PointerType> || std::is_same_v<D, EnumType>)
          return rules_.scalar_align(d.size);
        else if constexpr (std::is_same_v<D, UndefinedType>)
          return 1;
        else if constexpr (std::is_same_v<D, ArrayType>) {
          // A GCC vector is aligned to its size (up to 16).
          if (vector_ids_.contains(id.raw())) {
            std::uint64_t sz = size_of(id, depth + 1), a = 1;
            while (a < rules_.max_vector_alignment && a * 2 <= sz) a *= 2;
            return std::uint32_t(a);
          }
          return align_of(d.element, depth + 1);
        } else if constexpr (std::is_same_v<D, TypedefType>) {
          if (auto it = typedef_align_.find(id.raw()); it != typedef_align_.end()) return it->second;
          return align_of(d.target, depth + 1);
        } else if constexpr (std::is_same_v<D, QualifiedType>)
          return align_of(d.target, depth + 1);
        else if constexpr (std::is_same_v<D, AggregateType>) {
          if (id.is_local())
            if (auto it = local_align_.find(id.raw()); it != local_align_.end()) return it->second;
          if (d.alignment) return d.alignment;
          if (d.packed) return 1;
          std::uint32_t m = 1;
          for (const Field &f : d.fields) m = std::max(m, align_of(f.type, depth + 1));
          return m;
        } else
          return 1;
      },
      t->data);
  if (placeholder_ids_.contains(id.raw())) return rules_.scalar_align(rules_.int_size);
  return std::max<std::uint32_t>(a, 1);
}

TypeId Parser::strip(TypeId id) const {
  for (int k = 0; k < 64; ++k) {
    const Type *t = peek_type(id);
    if (!t) return id;
    if (const auto *d = t->as<TypedefType>()) id = d->target;
    else if (const auto *q = t->as<QualifiedType>()) id = q->target;
    else return id;
  }
  return id;
}

bool Parser::complete(TypeId id) const {
  TypeId s = strip(id);
  const Type *t = peek_type(s);
  if (!t) return false;
  if (const auto *a = t->as<AggregateType>()) return a->complete;
  if (const auto *e = t->as<EnumType>()) return e->complete;
  if (t->as<VoidType>() || t->as<FunctionType>()) return false;
  if (const auto *arr = t->as<ArrayType>()) return arr->count != 0 && complete(arr->element);
  return true;
}

TypeId Parser::int_type(std::uint32_t size, bool is_signed, IntRank rank) { return store_.int_type(size, is_signed, rank); }
TypeId Parser::plain_char() { return store_.int_type(1, rules_.char_signed, IntRank::PlainChar); }
TypeId Parser::void_type() { return store_.void_type(); }
TypeId Parser::pointer_to(TypeId t) { return add(PointerType{t, rules_.pointer_size, PointerKind::Pointer}); }

TypeId Parser::qualified(TypeId t, std::uint8_t quals) {
  if (!quals) return t;
  if (const Type *x = peek_type(t))
    if (const auto *q = x->as<QualifiedType>()) return add(QualifiedType{q->target, std::uint8_t(q->quals | quals)});
  return add(QualifiedType{t, quals});
}

TypeId Parser::undefined_placeholder(const Token &name) {
  if (auto it = unknown_types_.find(name.text); it != unknown_types_.end()) return it->second;
  if (unknown_reported_.insert(name.text).second)
    ctx_.error(name, "unknown type name '" + name.text + "'; using undefined" + std::to_string(rules_.int_size));
  TypeId id = store_.undefined(rules_.int_size);
  unknown_types_.emplace(name.text, id);
  placeholder_ids_.insert(id.raw());
  return id;
}

TypeId Parser::va_list_type() {
  if (va_list_) return *va_list_;
  const std::string &arch = ctx_.options.profile.arch;
  const bool windows = ctx_.options.profile.os == Os::Windows;
  TypeId vp = pointer_to(void_type());
  TypeId u32 = int_type(4, false, IntRank::Int);
  TypeId i32 = int_type(4, true, IntRank::Int);
  auto agg = [&](std::string name, std::vector<std::pair<std::string, TypeId>> fields) {
    TypeId node = g_.reserve();
    AggregateType a;
    a.name = std::move(name);
    std::vector<Member> members;
    for (auto &[n, t] : fields) members.push_back({n, t, std::nullopt, {}, {}});
    std::uint32_t align = 1;
    layout(a, members, {}, 0, align);
    local_align_[node.raw()] = align;
    const std::string key = "struct " + a.name;
    g_.set(node, a);
    local_aggregates_.push_back({node, rules_.pointer_size});
    if (!named_index_.contains(key)) {
      named_index_[key] = named_.size();
      named_.push_back({key, node, 0, 0});
    }
    return node;
  };
  TypeId t;
  if (windows || arch == "i386" || arch == "riscv64" || arch == "riscv32" || arch == "mips" || arch == "mipsel") {
    t = pointer_to(plain_char());
    if (!windows && arch != "i386") t = vp;
  } else if (arch == "x86_64") {
    TypeId tag = agg("__va_list_tag",
                     {{"gp_offset", u32}, {"fp_offset", u32}, {"overflow_arg_area", vp}, {"reg_save_area", vp}});
    t = add(ArrayType{tag, 1});
  } else if (arch == "aarch64") {
    t = agg("__va_list", {{"__stack", vp}, {"__gr_top", vp}, {"__vr_top", vp}, {"__gr_offs", i32}, {"__vr_offs", i32}});
  } else if (arch == "arm") {
    t = agg("__va_list", {{"__ap", vp}});
  } else if (arch == "powerpc") {
    TypeId u8 = int_type(1, false, IntRank::Char), u16 = int_type(2, false, IntRank::Short);
    TypeId tag = agg("__va_list_tag", {{"gpr", u8}, {"fpr", u8}, {"reserved", u16}, {"overflow_arg_area", vp},
                                       {"reg_save_area", vp}});
    t = add(ArrayType{tag, 1});
  } else {
    t = vp;
  }
  // As GCC and clang record it: a typedef named __builtin_va_list.
  t = add(TypedefType{"__builtin_va_list", t});
  if (!named_index_.contains("typedef __builtin_va_list")) {
    named_index_["typedef __builtin_va_list"] = named_.size();
    named_.push_back({"typedef __builtin_va_list", t, 0, 0});
  }
  va_list_ = t;
  return t;
}

std::optional<TypeId> Parser::target_builtin_type(const std::string &w) {
  // AArch64's NEON vector types (__Float32x4_t, __Int8x16_t, ...) and the
  // SVE types glibc's math-vector.h names; SVE's are sizeless.
  if (ctx_.options.profile.arch != "aarch64" || !w.starts_with("__") || !w.ends_with("_t")) return std::nullopt;
  if (w.starts_with("__SV")) return store_.undefined(16);
  static const std::vector<std::pair<std::string, int>> kinds = {
      {"__Int", 0}, {"__Uint", 1}, {"__Float", 2}, {"__Poly", 1}, {"__Bfloat", 3}};
  for (const auto &[prefix, k] : kinds) {
    if (!w.starts_with(prefix)) continue;
    std::string rest = w.substr(prefix.size(), w.size() - prefix.size() - 2);
    auto x = rest.find('x');
    if (x == std::string::npos) return std::nullopt;
    const int bits = std::atoi(rest.substr(0, x).c_str()), n = std::atoi(rest.substr(x + 1).c_str());
    if (bits <= 0 || n <= 0 || n > 64 || bits % 8) return std::nullopt;
    TypeId e = k == 2 ? store_.float_type(std::uint32_t(bits / 8), bits == 16 ? FloatKind::Half : bits == 32 ? FloatKind::Float : FloatKind::Double)
               : k == 3 ? store_.float_type(2, FloatKind::Half)
                        : int_type(std::uint32_t(bits / 8), k == 0, bits == 8 ? IntRank::Char : bits == 16 ? IntRank::Short : bits == 32 ? IntRank::Int : IntRank::Long);
    TypeId v = add(ArrayType{e, std::uint64_t(n)});
    vector_ids_.insert(v.raw());
    return v;
  }
  return std::nullopt;
}

TypeId Parser::sized_int_for_mode(TypeId base, std::uint32_t bytes, const Token &at) {
  TypeId s = strip(base);
  const Type *t = peek_type(s);
  bool is_signed = true;
  if (t) {
    if (const auto *i = t->as<IntType>()) is_signed = i->is_signed;
    else if (const auto *e = t->as<EnumType>()) is_signed = e->is_signed;
    else if (t->as<FloatType>()) {
      return store_.float_type(bytes, bytes == 4 ? FloatKind::Float : bytes == 8 ? FloatKind::Double : FloatKind::LongDouble);
    }
  }
  switch (bytes) {
    case 1: return int_type(1, is_signed, IntRank::Char);
    case 2: return int_type(2, is_signed, IntRank::Short);
    case 4: return int_type(4, is_signed, rules_.int_size == 4 ? IntRank::Int : IntRank::Long);
    case 8: return int_type(8, is_signed, rules_.long_size == 8 ? IntRank::Long : IntRank::LongLong);
    case 16: return int_type(16, is_signed, IntRank::Int128);
    default: ctx_.warning(at, "unsupported mode attribute"); return base;
  }
}

bool Parser::same_type(TypeId a, TypeId b, int depth) const {
  if (a == b) return true;
  if (depth > 32) return false;
  // A typedef names the same type as its target.
  auto untypedef = [&](TypeId id) {
    for (int k = 0; k < 64; ++k) {
      const Type *t = peek_type(id);
      const auto *d = t ? t->as<TypedefType>() : nullptr;
      if (!d) break;
      id = d->target;
    }
    return id;
  };
  a = untypedef(a);
  b = untypedef(b);
  if (a == b) return true;
  const Type *x = peek_type(a), *y = peek_type(b);
  if (!x || !y || x->kind() != y->kind()) return false;
  if (x->kind() == Kind::Aggregate || x->kind() == Kind::Enum) return false;  // tags are unique nodes
  Type xc = *x, yc = *y;
  std::vector<TypeId> xr, yr;
  for_each_ref(xc, [&](TypeId &r, EdgeKind) {
    xr.push_back(r);
    r = TypeId();
  });
  for_each_ref(yc, [&](TypeId &r, EdgeKind) {
    yr.push_back(r);
    r = TypeId();
  });
  if (!(xc == yc) || xr.size() != yr.size()) return false;
  for (std::size_t i = 0; i < xr.size(); ++i)
    if (!same_type(xr[i], yr[i], depth + 1)) return false;
  return true;
}

// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

std::string Parser::qualify(const std::string &name) const {
  std::string out;
  for (const std::string &s : scope_) {
    if (s.empty()) continue;
    out += s;
    out += "::";
  }
  return out + name;
}

const Parser::Sym *Parser::find_sym(const std::string &name) const {
  for (std::size_t k = scope_.size() + 1; k-- > 0;) {
    std::string q;
    for (std::size_t i = 0; i < k; ++i)
      if (!scope_[i].empty()) q += scope_[i] + "::";
    auto it = syms_.find(q + name);
    if (it != syms_.end()) return &it->second;
  }
  return nullptr;
}

Parser::Tag *Parser::find_tag(const std::string &name) {
  for (std::size_t k = scope_.size() + 1; k-- > 0;) {
    std::string q;
    for (std::size_t i = 0; i < k; ++i)
      if (!scope_[i].empty()) q += scope_[i] + "::";
    auto it = tags_.find(q + name);
    if (it != tags_.end()) return &it->second;
  }
  return nullptr;
}

std::optional<TypeId> Parser::existing(const std::string &key) {
  if (!ctx_.options.lookup || not_existing_.contains(key)) return std::nullopt;
  std::optional<TypeId> r = ctx_.options.lookup(key);
  if (!r || !r->valid() || r->is_local() || r->index() >= store_.size()) {
    not_existing_.insert(key);
    return std::nullopt;
  }
  if (used_existing_keys_.insert(key).second) used_existing_.emplace_back(key, *r);
  return r;
}

bool Parser::is_keyword(const std::string &w) const {
  static const std::set<std::string> c = {
      "auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else", "enum", "extern",
      "float", "for", "goto", "if", "inline", "int", "long", "register", "restrict", "return", "short", "signed",
      "sizeof", "static", "struct", "switch", "typedef", "union", "unsigned", "void", "volatile", "while", "_Alignas",
      "_Alignof", "_Atomic", "_Bool", "_Complex", "_Generic", "_Imaginary", "_Noreturn", "_Static_assert",
      "_Thread_local", "__attribute__", "__attribute", "__declspec", "__const", "__const__", "__volatile",
      "__volatile__", "__restrict", "__restrict__", "__inline", "__inline__", "__signed", "__signed__", "__int128",
      "__int64", "__int32", "__int16", "__int8", "__extension__", "typeof", "__typeof__", "__typeof", "asm", "__asm",
      "__asm__", "_Float16", "_Float32", "_Float64", "_Float128", "_Float32x", "_Float64x", "__float128", "__float80",
      "__fp16", "__bf16", "__builtin_va_list", "__thread", "__forceinline", "alignas", "alignof", "static_assert",
      "bool", "true", "false", "nullptr", "thread_local", "constexpr", "typeof_unqual", "__typeof_unqual__",
      "__complex__", "__complex", "__label__", "__auto_type", "__int128_t", "__uint128_t"};
  static const std::set<std::string> cpp = {
      "class", "namespace", "template", "typename", "using", "public", "private", "protected", "virtual", "explicit",
      "friend", "mutable", "operator", "new", "delete", "this", "throw", "try", "catch", "noexcept", "decltype",
      "wchar_t", "char8_t", "char16_t", "char32_t", "consteval", "constinit", "concept", "requires", "export",
      "override", "final", "static_cast", "dynamic_cast", "reinterpret_cast", "const_cast", "typeid"};
  if (c.contains(w) || is_cc_keyword(w) || is_ignored_qualifier(w)) return true;
  return cpp_ && cpp.contains(w);
}

bool Parser::is_type_name(const Token &t) {
  if (t.kind != TK::Ident) return false;
  if (const Sym *s = find_sym(t.text)) return s->kind == Sym::Kind::Typedef;
  if (is_keyword(t.text)) return false;
  if (auto e = existing("typedef " + t.text)) {
    syms_[t.text] = Sym{Sym::Kind::Typedef, *e, {}};
    existing_sym_keys_.insert(t.text);
    return true;
  }
  if (cpp_)
    for (const char *kw : {"struct ", "class ", "union ", "enum "})
      if (auto e = existing(kw + t.text)) {
        syms_[t.text] = Sym{Sym::Kind::Typedef, *e, {}};
        existing_sym_keys_.insert(t.text);
        return true;
      }
  // Ghidra's names for bytes of no known type (undefined, undefined1 ..
  // undefined8, any undefinedN), which revkit prints too: the undefined
  // type of that size, unless the sources declare the name themselves.
  if (t.text.starts_with("undefined")) {
    const std::string_view digits = std::string_view(t.text).substr(9);
    std::uint32_t n = digits.empty() ? 1 : 0;
    if (!digits.empty() && digits.size() <= 4 && digits.front() != '0' &&
        digits.find_first_not_of("0123456789") == std::string_view::npos)
      n = std::uint32_t(std::stoul(std::string(digits)));
    if (n > 0) {
      syms_[t.text] = Sym{Sym::Kind::Typedef, store_.undefined(n), {}};
      existing_sym_keys_.insert(t.text);
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Attributes
// ---------------------------------------------------------------------------

bool Parser::at_attribute() {
  const Token &t = peek();
  if (t.kind == TK::Ident)
    return t.text == "__attribute__" || t.text == "__attribute" || t.text == "__declspec" || t.text == "alignas" ||
           t.text == "_Alignas" || t.text == "__alignas" || t.text == "asm" || t.text == "__asm" ||
           t.text == "__asm__";
  return t.punct("[") && peek(1).punct("[");
}

void Parser::gnu_attribute_list(Attrs &a, bool declspec) {
  // Inside the parentheses: attr, attr(args), ...
  while (!at(")") && !at_eof()) {
    if (accept(",")) continue;
    Token name = next();
    if (name.kind != TK::Ident && name.kind != TK::Punct) fail(name, "expected an attribute name");
    std::string n = strip_underscores(name.text);
    if (accept("::")) n = strip_underscores(next().text);  // gnu::packed
    if (n == "packed") {
      a.packed = true;
      if (at("(")) skip_balanced();
    } else if (n == "aligned" || n == "align") {
      if (accept("(")) {
        Value v = const_expr();
        expect(")");
        if (v.v <= 0 || v.v > (1 << 28) || (v.v & (v.v - 1))) ctx_.warning(name, "invalid alignment");
        else a.aligned = std::max(a.aligned, static_cast<std::uint32_t>(v.v));
      } else {
        a.aligned = std::max<std::uint32_t>(a.aligned, rules_.biggest_alignment);
      }
    } else if (n == "mode" && !declspec) {
      expect("(");
      std::string m = strip_underscores(next().text);
      expect(")");
      if (m == "QI" || m == "byte") a.mode = 1;
      else if (m == "HI") a.mode = 2;
      else if (m == "SI") a.mode = 4;
      else if (m == "DI") a.mode = 8;
      else if (m == "TI") a.mode = 16;
      else if (m == "word" || m == "pointer" || m == "unwind_word") a.mode = rules_.pointer_size;
      else if (m == "SF") a.mode = 4;
      else if (m == "DF") a.mode = 8;
      else ctx_.warning(name, "ignoring mode(" + m + ")");
    } else if (n == "vector_size") {
      expect("(");
      Value v = const_expr();
      expect(")");
      if (v.v > 0 && v.v <= 4096) a.vector_size = static_cast<std::uint32_t>(v.v);
    } else if (n == "noreturn") {
      a.noreturn = true;
      if (at("(")) skip_balanced();
    } else if (auto cc = conv_keyword(n)) {
      a.cc = *cc;
      if (at("(")) skip_balanced();
    } else if (at("(")) {
      skip_balanced();
    }
  }
}

Attrs Parser::attributes() {
  Attrs a;
  for (;;) {
    const Token &t = peek();
    if (t.ident("__attribute__") || t.ident("__attribute")) {
      next();
      expect("(");
      expect("(");
      gnu_attribute_list(a, false);
      expect(")");
      expect(")");
    } else if (t.ident("__declspec")) {
      next();
      expect("(");
      gnu_attribute_list(a, true);
      expect(")");
    } else if (t.ident("alignas") || t.ident("_Alignas") || t.ident("__alignas")) {
      next();
      expect("(");
      if (starts_type_name()) {
        TypeId ty = type_name();
        a.aligned = std::max(a.aligned, align_of(ty));
      } else {
        Value v = const_expr();
        if (v.v > 0 && v.v <= (1 << 28) && !(v.v & (v.v - 1))) a.aligned = std::max(a.aligned, std::uint32_t(v.v));
      }
      expect(")");
    } else if (t.ident("asm") || t.ident("__asm") || t.ident("__asm__")) {
      next();
      while (peek().kind == TK::Ident && (peek().text == "volatile" || peek().text == "__volatile__")) next();
      if (at("(") && peek(1).kind == TK::String) {
        // An asm label: the name the declaration links as.
        next();
        std::string label;
        while (peek().kind == TK::String) label += string_value(next().text);
        if (at(")")) {
          next();
          a.asm_label = label;
        } else {
          while (!at_eof() && !at(")")) next();
          accept(")");
        }
      } else if (at("(")) {
        skip_balanced();
      }
    } else if (t.punct("[") && peek(1).punct("[")) {
      next();
      next();
      // [[gnu::packed, gnu::aligned(8)]] and friends; the rest is skipped.
      Attrs inner;
      try {
        gnu_attribute_list(inner, false);
      } catch (const ParseError &) {
        while (!at_eof() && !(at("]") && peek(1).punct("]"))) next();
      }
      a.merge(inner);
      // gnu_attribute_list stops at ')'; [[...]] ends with ]]
      while (!at_eof() && !(at("]") && peek(1).punct("]"))) next();
      expect("]");
      expect("]");
    } else {
      return a;
    }
  }
}

// ---------------------------------------------------------------------------
// Declarations
// ---------------------------------------------------------------------------

void Parser::single_declaration() {
  Specs s = decl_specs();
  if (!s.any_type() && !s.quals) fail(peek(), "expected a type");
  TypeId base = specs_type(s);
  Single out;
  if (!at_eof() && !at(";")) {
    Declarator d = declarator(true);
    if (d.attrs.mode) base = sized_int_for_mode(base, d.attrs.mode, d.where);
    out.function = !d.ops.empty() && d.ops.back().kind == DeclOp::Kind::Func;
    out.type = apply(base, d, out.function, d.attrs.cc ? d.attrs.cc : s.attrs.cc);
    out.name = d.name;
  } else {
    out.type = base;
  }
  accept(";");
  if (!at_eof()) fail(peek(), "unexpected '" + peek().text + "' after the declaration");
  single_out_ = std::move(out);
}

void Parser::run() {
  if (single_) {
    try {
      single_declaration();
    } catch (const ParseError &e) {
      ctx_.error(e.at, e.message);
    } catch (const LimitReached &l) {
      ctx_.result.limit_hit = true;
      ctx_.diag(Severity::Error, last_.file, last_.line, last_.col, "parse stopped: " + l.what);
    }
    try {
      finish();
    } catch (const LimitReached &l) {
      ctx_.result.limit_hit = true;
    }
    return;
  }
  try {
    while (!at_eof()) {
      const std::size_t before = ctx_.result.errors;
      Token start = peek();
      try {
        external_declaration();
      } catch (const ParseError &e) {
        ctx_.error(e.at, e.message);
        // Recover: past the next ';' at this level, or a balanced block.
        int depth = 0;
        bool progressed = false;
        for (;;) {
          const Token t = peek();
          if (t.kind == TK::Eof) break;
          if (t.punct("{") || t.punct("(") || t.punct("[")) {
            if (t.punct("{")) ++depth;
            skip_balanced();
            progressed = true;
            if (depth > 0) {
              --depth;
              if (peek().punct(";")) next();
              break;
            }
            continue;
          }
          if (t.punct("}")) {
            if (!blocks_.empty() && !progressed) break;  // closes a namespace or extern "C" block
            next();
            break;
          }
          next();
          progressed = true;
          if (t.punct(";")) break;
        }
        if (!progressed && peek().kind != TK::Eof && peek().file == start.file && peek().line == start.line &&
            peek().col == start.col && !peek().punct("}"))
          next();
      }
      (void)before;
    }
  } catch (const LimitReached &l) {
    ctx_.result.limit_hit = true;
    ctx_.diag(Severity::Error, last_.file, last_.line, last_.col, "parse stopped: " + l.what);
  }
  try {
    finish();
  } catch (const LimitReached &l) {
    ctx_.result.limit_hit = true;
    ctx_.diag(Severity::Error, last_.file, last_.line, last_.col, "parse stopped: " + l.what);
  }
}

void Parser::external_declaration() {
  const Token &t = peek();
  if (t.punct(";")) {
    next();
    return;
  }
  if (t.punct("}")) {
    if (blocks_.empty()) fail(t, "unexpected '}'");
    next();
    if (blocks_.back() == 'n' && !scope_.empty()) scope_.pop_back();
    blocks_.pop_back();
    return;
  }
  if (t.ident("_Static_assert") || t.ident("static_assert")) return static_assert_decl();
  if (t.ident("asm") || t.ident("__asm") || t.ident("__asm__")) {
    next();
    while (peek().kind == TK::Ident) next();
    if (at("(")) skip_balanced();
    accept(";");
    return;
  }
  if (cpp_) {
    if (t.ident("namespace") || (t.ident("inline") && peek(1).ident("namespace"))) return namespace_decl();
    if (t.ident("template")) return template_decl();
    if (t.ident("using")) return using_decl();
    if (t.ident("extern") && peek(1).kind == TK::String) {
      next();
      next();
      if (accept("{")) {
        blocks_.push_back('e');
        return;
      }
      return declaration(true);
    }
  } else if (t.ident("extern") && peek(1).kind == TK::String) {
    // extern "C" in a header read as C (#ifdef __cplusplus misused)
    next();
    next();
    if (accept("{")) {
      blocks_.push_back('e');
      return;
    }
  }
  declaration(true);
}

void Parser::namespace_decl() {
  accept("inline");
  next();  // namespace
  std::vector<std::string> names;
  while (peek().kind == TK::Ident) {
    names.push_back(next().text);
    if (!accept("::")) break;
    accept("inline");
  }
  attributes();
  if (accept("=")) {  // a namespace alias
    skip_to_semicolon();
    return;
  }
  expect("{");
  if (names.empty()) names.push_back("");  // an anonymous namespace: names stay unqualified
  // namespace a::b { ... } closes with one brace.
  std::string joined;
  for (const std::string &n : names) {
    if (!joined.empty() && !n.empty()) joined += "::";
    joined += n;
  }
  scope_.push_back(joined);
  blocks_.push_back('n');
  if (blocks_.size() > ctx_.options.limits.max_nesting) throw LimitReached{"namespaces nested too deeply"};
}

void Parser::template_decl() {
  const Token at = next();  // template
  if (at_eof()) return;
  if (accept("<")) {
    int depth = 1;
    while (depth > 0 && !at_eof()) {
      Token t = next();
      if (t.punct("<")) ++depth;
      else if (t.punct(">")) --depth;
      else if (t.punct(">>")) depth -= 2;
      else if (t.punct("(")) {
        la_.push_front(t);
        skip_balanced();
      }
    }
  }
  ctx_.diag(Severity::Warning, at, "template declaration skipped");
  skip_to_semicolon();
}

void Parser::using_decl() {
  const Token at = next();  // using
  if (peek().ident("namespace")) {
    skip_to_semicolon();
    return;
  }
  if (peek().kind == TK::Ident && peek(1).punct("=")) {
    Token name = next();
    next();
    attributes();
    TypeId t = type_name();
    expect(";");
    define_typedef(name.text, t, name, {});
    return;
  }
  (void)at;
  skip_to_semicolon();
}

void Parser::static_assert_decl() {
  Token at = next();
  expect("(");
  std::optional<Value> v;
  try {
    v = const_expr();
  } catch (const ParseError &e) {
    ctx_.warning(e.at, "could not evaluate the static assertion: " + e.message);
    while (!at_eof() && !this->at(")")) {
      if (this->at("(")) skip_balanced();
      else next();
    }
  }
  std::string msg;
  if (accept(",")) {
    while (peek().kind == TK::String) msg += string_value(next().text);
  }
  expect(")");
  accept(";");
  if (v && v->v == 0) ctx_.error(at, "static assertion failed" + (msg.empty() ? std::string() : ": " + msg));
}

bool Parser::starts_type_name(std::size_t n) {
  const Token &t = peek(n);
  if (t.kind != TK::Ident) return false;
  static const std::set<std::string> kw = {
      "void", "char", "short", "int", "long", "float", "double", "signed", "unsigned", "_Bool", "_Complex",
      "struct", "union", "enum", "const", "volatile", "restrict", "_Atomic", "__int128", "__int64", "__int32",
      "__int16", "__int8", "__signed", "__signed__", "__const", "__const__", "__volatile", "__volatile__",
      "__restrict", "__restrict__", "typeof", "__typeof__", "__typeof", "_Float16", "_Float32", "_Float64",
      "_Float128", "_Float32x", "_Float64x", "__float128", "__float80", "__fp16", "__bf16", "__builtin_va_list",
      "__extension__", "__complex__", "__complex", "__int128_t", "__uint128_t", "__attribute__", "typeof_unqual",
      "__typeof_unqual__"};
  if (kw.contains(t.text)) return true;
  if (t.text == "bool" && (cpp_ || !find_sym("bool"))) return true;
  if (cpp_ && (t.text == "class" || t.text == "wchar_t" || t.text == "char8_t" || t.text == "char16_t" ||
               t.text == "char32_t" || t.text == "typename" || t.text == "decltype"))
    return true;
  return is_type_name(t);
}

Parser::Specs Parser::decl_specs(bool member_ctx) {
  Specs s;
  s.where = peek();
  for (;;) {
    const Token &t = peek();
    if (t.punct("[") && peek(1).punct("[")) {
      s.attrs.merge(attributes());
      continue;
    }
    if (t.kind != TK::Ident) break;
    const std::string w = t.text;
    if (w == "typedef") s.is_typedef = true;
    else if (w == "extern") {
      s.is_extern = true;
      next();
      if (peek().kind == TK::String) next();  // extern "C" int f();
      continue;
    } else if (w == "static") s.is_static = true;
    else if (w == "register" || (w == "auto" && !cpp_) || w == "_Thread_local" || w == "__thread" ||
             w == "thread_local" || w == "mutable" || w == "explicit" || w == "consteval" || w == "constinit" ||
             w == "__label__") {
    } else if (w == "constexpr") s.is_constexpr = true;
    else if (w == "inline" || w == "__inline" || w == "__inline__" || w == "__forceinline")
      s.is_inline = true;
    else if (w == "_Noreturn") s.attrs.noreturn = true;
    else if (w == "virtual") s.is_virtual = true;
    else if (w == "friend") s.is_friend = true;
    else if (w == "const" || w == "__const" || w == "__const__") s.quals |= kConst;
    else if (w == "volatile" || w == "__volatile" || w == "__volatile__") s.quals |= kVolatile;
    else if (w == "restrict" || w == "__restrict" || w == "__restrict__") s.quals |= kRestrict;
    else if (w == "_Atomic") {
      const Token at = next();
      if (accept("(")) {
        TypeId inner = type_name();
        expect(")");
        if (s.named) fail(at, "two types in one declaration");
        s.named = qualified(inner, kAtomic);
      } else {
        s.quals |= kAtomic;
      }
      continue;
    } else if (is_ignored_qualifier(w)) {
    } else if (is_cc_keyword(w)) {
      if (auto cc = conv_keyword(w)) s.attrs.cc = *cc;
    } else if (w == "__attribute__" || w == "__attribute" || w == "__declspec" || w == "alignas" || w == "_Alignas" ||
               w == "__alignas") {
      s.attrs.merge(attributes());
      continue;
    } else if (w == "struct" || w == "union" || (w == "class" && cpp_)) {
      if (s.any_type()) fail(t, "two types in one declaration");
      Token kw = next();
      s.named = struct_spec(kw, s);
      continue;
    } else if (w == "enum") {
      if (s.any_type()) fail(t, "two types in one declaration");
      Token kw = next();
      s.named = enum_spec(kw, s);
      continue;
    } else if (w == "typeof" || w == "__typeof__" || w == "__typeof" || w == "typeof_unqual" ||
               w == "__typeof_unqual__" || (cpp_ && w == "decltype")) {
      Token kw = next();
      expect("(");
      std::optional<TypeId> ty;
      if (starts_type_name()) {
        ty = type_name();
      } else {
        try {
          ty = expr_type(0);
        } catch (const ParseError &) {
        }
        if (!ty) {
          ctx_.warning(kw, w + " of an expression revkit can't type; using undefined");
          ty = store_.undefined(rules_.int_size);
        }
        while (!at_eof() && !at(")")) {
          if (at("(")) skip_balanced();
          else next();
        }
      }
      expect(")");
      if (s.named) fail(kw, "two types in one declaration");
      s.named = *ty;
      continue;
    } else if (cpp_ && w == "typename") {
    } else if (w == "void" || w == "char" || w == "short" || w == "int" || w == "long" || w == "float" ||
               w == "double" || w == "signed" || w == "__signed" || w == "__signed__" || w == "unsigned" ||
               w == "_Bool" || w == "_Complex" || w == "__complex__" || w == "__complex" || w == "__int128" ||
               w == "__int64" || w == "__int32" || w == "__int16" || w == "__int8" || w.starts_with("_Float") ||
               w == "__float128" || w == "__float80" || w == "__fp16" || w == "__bf16" || w == "__int128_t" ||
               w == "__uint128_t" || w == "__builtin_va_list" ||
               (w == "bool" && (cpp_ || !find_sym("bool"))) ||
               (cpp_ && (w == "wchar_t" || w == "char8_t" || w == "char16_t" || w == "char32_t"))) {
      type_keyword(s, t);
    } else {
      // An identifier: a type name, the declarator's name, or junk.
      if (s.any_type()) break;
      if (is_type_name(t)) {
        const Sym *sym = find_sym(w);
        s.named = sym ? sym->type : *existing("typedef " + w);
        s.typedef_name = true;
        next();
        // C++: A::B names a member type.
        while (cpp_ && at("::") && peek(1).kind == TK::Ident) {
          next();
          Token m = next();
          std::string q = w + "::" + m.text;
          if (const Sym *qs = find_sym(q)) s.named = qs->type;
          else if (Tag *tg = find_tag(q)) s.named = tg->id;
        }
        continue;
      }
      if (is_keyword(w)) break;
      if (auto vt = target_builtin_type(w)) {
        if (s.named) fail(t, "two types in one declaration");
        s.named = *vt;
        next();
        continue;
      }
      const Token &n1 = peek(1);
      const bool declarator_follows =
          (n1.kind == TK::Ident && !starts_type_name(1) && !is_keyword(n1.text)) || n1.punct("*") ||
          (n1.punct("(") && (peek(2).punct("*") || peek(2).punct("^"))) || (cpp_ && (n1.punct("&") || n1.punct("&&"))) ||
          (member_ctx && (n1.punct(",") || n1.punct(")") || n1.punct("[")));
      if (declarator_follows || (n1.kind == TK::Ident && is_cc_keyword(n1.text))) {
        s.named = undefined_placeholder(t);
        next();
        continue;
      }
      if (n1.kind == TK::Ident && (starts_type_name(1) || is_keyword(n1.text))) {
        // Probably a decoration macro the profile doesn't define (FOO_API).
        if (unknown_reported_.insert(w).second) ctx_.warning(t, "ignoring unknown identifier '" + w + "'");
        next();
        continue;
      }
      break;
    }
    next();
  }
  return s;
}

void Parser::type_keyword(Specs &s, const Token &t) {
  const std::string &w = t.text;
  auto named = [&](TypeId id) {
    if (s.named) fail(t, "two types in one declaration");
    s.named = id;
  };
  if (w == "void") ++s.n_void;
  else if (w == "char") ++s.n_char;
  else if (w == "short") ++s.n_short;
  else if (w == "int") ++s.n_int;
  else if (w == "long") ++s.n_long;
  else if (w == "float") ++s.n_float;
  else if (w == "double") ++s.n_double;
  else if (w == "signed" || w == "__signed" || w == "__signed__") ++s.n_signed;
  else if (w == "unsigned") ++s.n_unsigned;
  else if (w == "_Bool" || w == "bool") ++s.n_bool;
  else if (w == "_Complex" || w == "__complex__" || w == "__complex") ++s.n_complex;
  else if (w == "__int128") ++s.n_int128;
  else if (w == "__int64") s.n_long += 2;
  else if (w == "__int32") ++s.n_int;
  else if (w == "__int16") ++s.n_short;
  else if (w == "__int8") ++s.n_char;
  else if (w == "__int128_t") named(int_type(16, true, IntRank::Int128));
  else if (w == "__uint128_t") named(int_type(16, false, IntRank::Int128));
  else if (w == "_Float16" || w == "__fp16" || w == "__bf16") named(store_.float_type(2, FloatKind::Half));
  else if (w == "_Float32") ++s.n_float;
  else if (w == "_Float64" || w == "_Float32x") ++s.n_double;
  else if (w == "_Float64x" || w == "__float80") named(store_.float_type(rules_.long_double_size, FloatKind::LongDouble));
  else if (w == "_Float128" || w == "__float128") named(store_.float_type(16, FloatKind::Float128));
  else if (w.starts_with("_Float")) {
    ctx_.warning(t, "unsupported type " + w + "; using double");
    ++s.n_double;
  } else if (w == "__builtin_va_list") named(va_list_type());
  else if (w == "wchar_t") named(int_type(rules_.wchar_size, rules_.wchar_signed, IntRank::WChar));
  else if (w == "char8_t") named(int_type(1, false, IntRank::Char8));
  else if (w == "char16_t") named(int_type(2, false, IntRank::Char16));
  else if (w == "char32_t") named(int_type(4, false, IntRank::Char32));
}

TypeId Parser::base_type(const Specs &s) {
  const bool u = s.n_unsigned > 0;
  if (s.named) {
    if (s.n_unsigned || s.n_signed || s.n_long || s.n_short) {
      // unsigned __int128_t and the like.
      if (const Type *t = peek_type(strip(*s.named)))
        if (const auto *i = t->as<IntType>()) return int_type(i->size, !u, i->rank);
    }
    return *s.named;
  }
  if (s.n_void) return void_type();
  if (s.n_bool) return store_.bool_type(1);
  if (s.n_char) {
    if (s.n_signed) return int_type(1, true, IntRank::Char);
    if (u) return int_type(1, false, IntRank::Char);
    return plain_char();
  }
  if (s.n_float) return store_.intern(FloatType{s.n_complex ? rules_.float_size * 2 : rules_.float_size, FloatKind::Float, s.n_complex > 0});
  if (s.n_double) {
    if (s.n_long)
      return store_.intern(FloatType{s.n_complex ? rules_.long_double_size * 2 : rules_.long_double_size,
                                     FloatKind::LongDouble, s.n_complex > 0});
    return store_.intern(FloatType{s.n_complex ? rules_.double_size * 2 : rules_.double_size, FloatKind::Double, s.n_complex > 0});
  }
  if (s.n_int128) return int_type(16, !u, IntRank::Int128);
  if (s.n_short) return int_type(rules_.short_size, !u, IntRank::Short);
  if (s.n_long >= 2) return int_type(rules_.long_long_size, !u, IntRank::LongLong);
  if (s.n_long == 1) return int_type(rules_.long_size, !u, IntRank::Long);
  if (s.n_int || s.n_signed || s.n_unsigned) return int_type(rules_.int_size, !u, IntRank::Int);
  if (s.n_complex) return store_.intern(FloatType{rules_.double_size * 2, FloatKind::Double, true});
  ctx_.warning(s.where, "type specifier missing, defaults to 'int'");
  return int_type(rules_.int_size, true, IntRank::Int);
}

TypeId Parser::specs_type(Specs &s) {
  TypeId t = base_type(s);
  if (s.attrs.mode) t = sized_int_for_mode(t, s.attrs.mode, s.where);
  if (s.attrs.vector_size) {
    std::uint64_t es = size_of(t);
    if (es) {
      t = add(ArrayType{t, s.attrs.vector_size / es});
      vector_ids_.insert(t.raw());
    }
  }
  return qualified(t, s.quals);
}

bool Parser::is_nested_declarator_start() {
  // At '(': a parenthesized declarator, or a parameter list?
  const Token &n = peek(1);
  if (n.punct("*") || n.punct("^") || n.punct("(") || n.punct("[")) return true;
  if (cpp_ && (n.punct("&") || n.punct("&&") || n.punct("::"))) return true;
  if (n.kind == TK::Ident) {
    if (is_cc_keyword(n.text) || is_ignored_qualifier(n.text)) return true;
    if (n.text == "__attribute__" || n.text == "__attribute" || n.text == "__declspec") return true;
    if (starts_type_name(1) || is_keyword(n.text)) return false;
    return true;
  }
  return false;
}

Parser::Declarator Parser::declarator(bool abstract_ok, int depth) {
  ctx_.check_nesting(static_cast<std::uint32_t>(depth));
  Declarator d;
  d.where = peek();
  std::vector<DeclOp> ptrs;
  for (;;) {
    const Token &t = peek();
    if (t.punct("*") || t.punct("^")) {
      next();
      DeclOp op;
      op.kind = DeclOp::Kind::Ptr;
      for (;;) {
        const Token &q = peek();
        if (q.kind != TK::Ident && !(q.punct("[") && peek(1).punct("["))) break;
        if (q.text == "const" || q.text == "__const" || q.text == "__const__") op.quals |= kConst;
        else if (q.text == "volatile" || q.text == "__volatile" || q.text == "__volatile__") op.quals |= kVolatile;
        else if (q.text == "restrict" || q.text == "__restrict" || q.text == "__restrict__") op.quals |= kRestrict;
        else if (q.text == "_Atomic") op.quals |= kAtomic;
        else if (is_ignored_qualifier(q.text)) {
        } else if (is_cc_keyword(q.text)) {
          if (auto cc = conv_keyword(q.text)) d.attrs.cc = *cc;
        } else if (at_attribute() && !q.ident("asm") && !q.ident("__asm") && !q.ident("__asm__")) {
          d.attrs.merge(attributes());
          continue;
        } else {
          break;
        }
        next();
      }
      ptrs.push_back(op);
    } else if (cpp_ && (t.punct("&") || t.punct("&&"))) {
      DeclOp op;
      op.kind = t.punct("&") ? DeclOp::Kind::LRef : DeclOp::Kind::RRef;
      next();
      ptrs.push_back(op);
    } else if (t.kind == TK::Ident && is_cc_keyword(t.text)) {
      if (auto cc = conv_keyword(t.text)) d.attrs.cc = *cc;
      next();
    } else if (t.kind == TK::Ident && is_ignored_qualifier(t.text)) {
      next();
    } else if (t.kind == TK::Ident && (t.text == "__attribute__" || t.text == "__attribute" || t.text == "__declspec")) {
      d.attrs.merge(attributes());
    } else {
      break;
    }
  }
  std::optional<Declarator> inner;
  if (at("(") && is_nested_declarator_start()) {
    next();
    inner = declarator(abstract_ok, depth + 1);
    expect(")");
  } else if (peek().kind == TK::Ident && !is_keyword(peek().text)) {
    // After the specifiers, an identifier is the declarator's name even if
    // it names a type elsewhere (a parameter called `name`).
    Token n = next();
    d.name = n.text;
    d.where = n;
    if (cpp_)
      while (at("::")) {
        next();
        d.qualified_name = true;
        if (accept("~")) d.name += "::~";
        else d.name += "::";
        if (peek().ident("operator")) {
          d.operator_name = true;
          break;
        }
        if (peek().kind != TK::Ident) fail(peek(), "expected a name after '::'");
        d.name += next().text;
      }
  } else if (cpp_ && peek().ident("operator")) {
    d.operator_name = true;
  } else if (cpp_ && peek().punct("~") && peek(1).kind == TK::Ident) {
    next();
    d.name = "~" + next().text;
  } else if (!abstract_ok) {
    const Token &t = peek();
    fail(t, t.kind == TK::Eof ? "expected a declarator at end of input" : "expected a declarator before '" + t.text + "'");
  }
  if (d.operator_name) {
    // operator+, operator(), operator new[], operator int: up to its parameters.
    Token op = next();
    d.where = op;
    if (at("(") && peek(1).punct(")")) {
      next();
      next();
    }
    while (!at_eof() && !at("(") && !at(";")) next();
  }
  std::vector<DeclOp> suffixes;
  declarator_suffixes(suffixes, depth);
  d.attrs.merge(attributes());
  d.ops = std::move(ptrs);
  for (auto it = suffixes.rbegin(); it != suffixes.rend(); ++it) d.ops.push_back(std::move(*it));
  if (inner) {
    for (DeclOp &op : inner->ops) d.ops.push_back(std::move(op));
    d.name = inner->name;
    d.where = inner->where;
    d.qualified_name = inner->qualified_name;
    d.operator_name = d.operator_name || inner->operator_name;
    Attrs merged = inner->attrs;
    merged.merge(d.attrs);
    d.attrs = merged;
  }
  return d;
}

void Parser::declarator_suffixes(std::vector<DeclOp> &suffixes, int depth) {
  for (;;) {
    if (at("[") && !peek(1).punct("[")) {
      Token open = next();
      DeclOp op;
      op.kind = DeclOp::Kind::Array;
      while (peek().kind == TK::Ident && (peek().text == "static" || peek().text == "const" || peek().text == "restrict" ||
                                          peek().text == "volatile" || peek().text == "__restrict" ||
                                          peek().text == "__restrict__" || peek().text == "_Atomic"))
        next();
      if (accept("]")) {
        op.count = 0;
      } else if (at("*") && peek(1).punct("]")) {
        next();
        next();
      } else {
        try {
          Value v = const_expr();
          if (v.v < 0 && !v.is_unsigned) {
            ctx_.error(open, "array size is negative");
          } else {
            op.count = static_cast<std::uint64_t>(v.v);
            if (op.count > (std::uint64_t(1) << 48)) {
              ctx_.error(open, "array is too large");
              op.count = 0;
            }
          }
        } catch (const ParseError &e) {
          // A parameter's array size needn't be constant (it is a pointer).
          if (!in_params_)
            ctx_.warning(open, "array size is not a constant expression (" + e.message + "); size unknown");
          while (!at_eof() && !at("]")) {
            if (at("(") || at("[") || at("{")) skip_balanced();
            else next();
          }
        }
        expect("]");
      }
      suffixes.push_back(std::move(op));
    } else if (at("(")) {
      DeclOp op;
      op.kind = DeclOp::Kind::Func;
      op.func = params(depth);
      // C++: const, volatile, &, &&, noexcept, throw(), override, final, -> T
      if (cpp_) {
        for (;;) {
          const Token &t = peek();
          if (t.ident("const") || t.ident("volatile") || t.ident("override") || t.ident("final") || t.punct("&") ||
              t.punct("&&")) {
            next();
          } else if (t.ident("noexcept") || t.ident("throw")) {
            next();
            if (at("(")) skip_balanced();
          } else if (t.punct("->")) {
            next();
            type_name();
          } else {
            break;
          }
        }
      }
      suffixes.push_back(std::move(op));
    } else {
      return;
    }
  }
}

std::shared_ptr<Parser::FuncInfo> Parser::params(int depth) {
  ctx_.check_nesting(static_cast<std::uint32_t>(depth + 1));
  expect("(");
  ++in_params_;
  struct Leave {
    int &n;
    ~Leave() { --n; }
  } leave{in_params_};
  auto f = std::make_shared<FuncInfo>();
  if (accept(")")) {
    if (!cpp_) f->unprototyped = true;
    return f;
  }
  if (peek().ident("void") && peek(1).punct(")")) {
    next();
    next();
    return f;
  }
  // K&R: an identifier list.
  if (!cpp_ && peek().kind == TK::Ident && !starts_type_name() && !is_keyword(peek().text) &&
      (peek(1).punct(",") || peek(1).punct(")"))) {
    bool all = true;
    for (std::size_t k = 0;; k += 2) {
      const Token &a = peek(k), &b = peek(k + 1);
      if (a.kind != TK::Ident || starts_type_name(k)) {
        all = false;
        break;
      }
      if (b.punct(")")) break;
      if (!b.punct(",")) {
        all = false;
        break;
      }
      if (k > 512) break;
    }
    if (all) {
      while (!at_eof() && !accept(")")) next();
      f->unprototyped = true;
      return f;
    }
  }
  for (;;) {
    if (accept("...")) {
      f->varargs = true;
      expect(")");
      break;
    }
    Specs s = decl_specs(true);
    if (!s.any_type() && !s.quals) fail(peek(), "expected a parameter declaration before '" + peek().text + "'");
    Declarator d = declarator(true, depth + 1);
    TypeId base = specs_type(s);
    if (d.attrs.mode) base = sized_int_for_mode(base, d.attrs.mode, d.where);
    TypeId t = apply(base, d, false, d.attrs.cc ? d.attrs.cc : s.attrs.cc);
    // Arrays and functions as parameters are pointers.
    // (Copied: adding a type can move the graph's nodes.)
    const Type st = get(strip(t));
    if (const auto *arr = st.as<ArrayType>()) t = pointer_to(arr->element);
    else if (st.as<FunctionType>()) t = pointer_to(t);
    if (accept("=")) skip_initializer();  // a C++ default argument
    f->params.push_back({d.name, t});
    if (f->params.size() > 4096) fail(peek(), "too many parameters");
    if (accept(",")) continue;
    expect(")");
    break;
  }
  return f;
}

TypeId Parser::apply(TypeId base, const Declarator &d, bool keep_names, std::optional<CallConv> cc) {
  TypeId t = base;
  // The function a declarator declares is its last function operation.
  std::size_t last_func = d.ops.size();
  for (std::size_t i = 0; i < d.ops.size(); ++i)
    if (d.ops[i].kind == DeclOp::Kind::Func) last_func = i;
  for (std::size_t i = 0; i < d.ops.size(); ++i) {
    const DeclOp &op = d.ops[i];
    switch (op.kind) {
      case DeclOp::Kind::Ptr: t = qualified(pointer_to(t), op.quals); break;
      case DeclOp::Kind::LRef: t = add(PointerType{t, rules_.pointer_size, PointerKind::LValueRef}); break;
      case DeclOp::Kind::RRef: t = add(PointerType{t, rules_.pointer_size, PointerKind::RValueRef}); break;
      case DeclOp::Kind::Array: {
        const Type *et = peek_type(strip(t));
        if (et && et->as<FunctionType>()) fail(d.where, "array of functions");
        t = add(ArrayType{t, op.count});
        break;
      }
      case DeclOp::Kind::Func: {
        const Type *rt = peek_type(strip(t));
        if (rt && (rt->as<FunctionType>() || (rt->as<ArrayType>() && !vector_ids_.contains(strip(t).raw()))))
          fail(d.where, "a function can't return a function or an array");
        FunctionType fn;
        fn.ret = t;
        fn.varargs = op.func->varargs || op.func->unprototyped;
        const bool names = keep_names && i == last_func && i == d.ops.size() - 1;
        for (const Param &p : op.func->params) fn.params.push_back({names ? p.name : std::string(), p.type});
        if (i == last_func && cc) {
          // What the compiler records: the target's own convention is the default.
          const std::string &arch = ctx_.options.profile.arch;
          const bool win = ctx_.options.profile.os == Os::Windows;
          CallConv c = *cc;
          if (arch != "i386") {
            if (c == CallConv::Cdecl || c == CallConv::Stdcall || c == CallConv::Fastcall || c == CallConv::Thiscall ||
                c == CallConv::Pascal)
              c = CallConv::Default;
            if ((c == CallConv::Ms64 && win) || (c == CallConv::SysV && !win)) c = CallConv::Default;
          } else if (c == CallConv::Cdecl) {
            c = CallConv::Default;
          }
          fn.cc = c;
        }
        t = add(std::move(fn));
        break;
      }
    }
  }
  return t;
}

TypeId Parser::type_name() {
  Specs s = decl_specs(true);
  if (!s.any_type() && !s.quals) fail(peek(), "expected a type name");
  Declarator d = declarator(true);
  if (!d.name.empty()) fail(d.where, "unexpected name '" + d.name + "' in a type name");
  TypeId base = specs_type(s);
  return apply(base, d, false, d.attrs.cc ? d.attrs.cc : s.attrs.cc);
}

void Parser::define_typedef(const std::string &name, TypeId type, const Token &where, const Attrs &attrs) {
  if (name.empty()) return;
  const std::string key = qualify(name);
  TypeId id = add(TypedefType{key, type});
  if (attrs.aligned) typedef_align_[id.raw()] = attrs.aligned;
  auto it = syms_.find(key);
  if (it != syms_.end()) {
    const Sym &old = it->second;
    if (old.kind != Sym::Kind::Typedef) {
      ctx_.error(where, "'" + name + "' redeclared as a different kind of symbol");
      return;
    }
    if (!existing_sym_keys_.contains(key)) {
      const Type *ot = peek_type(old.type);
      const auto *otd = ot ? ot->as<TypedefType>() : nullptr;
      if (otd && !same_type(otd->target, type))
        ctx_.warning(where, "typedef redefinition with a different type for '" + name + "'; keeping the first");
      return;
    }
    existing_sym_keys_.erase(key);
  }
  syms_[key] = Sym{Sym::Kind::Typedef, id, {}};
  const std::string nkey = "typedef " + key;
  if (!named_index_.contains(nkey)) {
    named_index_[nkey] = named_.size();
    named_.push_back({nkey, id, where.file, where.line});
  }
}

void Parser::record_function(const std::string &name, TypeId type, const Token &where, bool defined,
                             const Attrs &attrs) {
  if (name.empty()) return;
  const std::string key = qualify(name);
  syms_[key] = Sym{Sym::Kind::Function, type, {}};
  if (where.file < ctx_.files.size() &&
      (ctx_.files[where.file].builtin || (ctx_.files[where.file].system && !ctx_.options.system_prototypes)))
    return;
  auto it = proto_index_.find(key);
  if (it == proto_index_.end()) {
    proto_index_[key] = protos_.size();
    protos_.push_back({key, type, where.file, where.line, defined, attrs.asm_label, attrs.noreturn});
    return;
  }
  ProtoEntry &p = protos_[it->second];
  // A later declaration may add a label or noreturn (glibc declares some
  // functions twice).
  const std::string label = attrs.asm_label.empty() ? p.asm_label : attrs.asm_label;
  const bool noreturn = p.noreturn || attrs.noreturn;
  // A definition replaces a declaration, except in a library's headers
  // (system_prototypes): there the declaration is the interface, and a
  // later inline definition (glibc's fortified printf) only an
  // implementation with other parameter names.
  if ((defined || !p.defined) && !ctx_.options.system_prototypes)
    p = {key, type, where.file, where.line, defined || p.defined, label, noreturn};
  else {
    p.asm_label = label;
    p.noreturn = noreturn;
  }
}

void Parser::skip_function_body() { skip_balanced(); }

void Parser::declaration(bool top_level) {
  Specs s = decl_specs();
  if (accept(";")) {
    if (!s.any_type()) ctx_.warning(s.where, "declaration does nothing");
    return;
  }
  if (!s.any_type() && !s.quals && !s.is_typedef && !s.is_extern && !s.is_static) {
    const Token &t = peek();
    fail(t, t.kind == TK::Ident ? "unknown type name or declaration '" + t.text + "'"
                                : "expected a declaration before '" + t.text + "'");
  }
  for (;;) {
    Declarator d = declarator(false);
    TypeId base = specs_type(s);
    if (d.attrs.mode) base = sized_int_for_mode(base, d.attrs.mode, d.where);
    if (d.attrs.vector_size) {
      std::uint64_t es = size_of(base);
      if (es) {
        base = add(ArrayType{base, d.attrs.vector_size / es});
        vector_ids_.insert(base.raw());
      }
    }
    const std::optional<CallConv> cc = d.attrs.cc ? d.attrs.cc : s.attrs.cc;
    const bool is_func = !d.ops.empty() && d.ops.back().kind == DeclOp::Kind::Func;
    Attrs fattrs = s.attrs;
    fattrs.merge(d.attrs);
    if (s.is_typedef) {
      TypeId t = apply(base, d, false, cc);
      Attrs a = s.attrs;
      a.merge(d.attrs);
      define_typedef(d.name, t, d.where, a);
    } else if (is_func) {
      TypeId t = apply(base, d, true, cc);
      const bool method = d.qualified_name || d.operator_name;
      if (at("{") || (cpp_ && at(":") && top_level)) {
        if (at(":")) {  // a constructor's initializer list
          while (!at_eof() && !at("{")) {
            if (at("(")) skip_balanced();
            else next();
          }
        }
        if (!method) record_function(d.name, t, d.where, true, fattrs);
        skip_function_body();
        return;
      }
      if (!cpp_ && d.ops.back().func->unprototyped && top_level && peek().kind == TK::Ident) {
        // K&R parameter declarations, then the body.
        while (!at_eof() && !at("{")) {
          if (at("(") || at("[")) skip_balanced();
          else next();
        }
        if (!method) record_function(d.name, t, d.where, true, fattrs);
        skip_function_body();
        return;
      }
      if (!method) record_function(d.name, t, d.where, false, fattrs);
      if (accept("=")) skip_initializer();  // = 0, = default, = delete
    } else {
      TypeId t = apply(base, d, false, cc);
      if (!d.name.empty()) syms_[qualify(d.name)] = Sym{Sym::Kind::Object, t, {}};
      if (accept("=")) skip_initializer();
      else if (cpp_ && at("{")) skip_balanced();
    }
    if (accept(",")) continue;
    expect(";");
    return;
  }
}

// ---------------------------------------------------------------------------
// Structs, unions, classes
// ---------------------------------------------------------------------------

TypeId Parser::tag_reference(const std::string &name, Kind kind, AggregateKind agg, const Token &where,
                             bool declaration_only) {
  const char *kw = kind == Kind::Enum ? "enum " : agg == AggregateKind::Union ? "union " : "struct ";
  if (!declaration_only) {
    if (Tag *t = find_tag(name)) {
      if (t->kind != kind || (kind == Kind::Aggregate && (t->agg == AggregateKind::Union) != (agg == AggregateKind::Union)))
        ctx_.error(where, "use of '" + name + "' with a tag type that does not match its previous declaration");
      return t->id;
    }
    if (auto e = existing(kw + name)) {
      tags_[name] = Tag{*e, kind, agg, true, true, where.file, where.line};
      return *e;
    }
    if (agg == AggregateKind::Class)
      if (auto e = existing(std::string("class ") + name)) {
        tags_[name] = Tag{*e, kind, agg, true, true, where.file, where.line};
        return *e;
      }
  }
  const std::string key = qualify(name);
  if (auto it = tags_.find(key); it != tags_.end()) return it->second.id;
  TypeId id = g_.reserve();
  tags_[key] = Tag{id, kind, agg, false, false, where.file, where.line};
  if (cpp_ && !syms_.contains(key)) syms_[key] = Sym{Sym::Kind::Typedef, id, {}};
  return id;
}

TypeId Parser::struct_spec(const Token &kw, Specs &s) {
  const AggregateKind agg = kw.text == "union" ? AggregateKind::Union
                            : kw.text == "class" ? AggregateKind::Class
                                                 : AggregateKind::Struct;
  Attrs attrs = attributes();
  std::string name;
  Token name_tok = kw;
  if (peek().kind == TK::Ident && !is_keyword(peek().text)) {
    name_tok = next();
    name = name_tok.text;
    while (cpp_ && at("::") && peek(1).kind == TK::Ident) {
      next();
      name += "::" + next().text;
    }
  }
  attrs.merge(attributes());
  if (cpp_ && (peek().ident("final") || peek().ident("sealed"))) next();
  // C++ base classes.
  std::vector<TypeId> bases;
  if (cpp_ && at(":") && !peek(1).punct(":")) {
    next();
    for (;;) {
      while (peek().ident("public") || peek().ident("private") || peek().ident("protected") || peek().ident("virtual"))
        next();
      TypeId b = type_name();
      bases.push_back(b);
      if (!accept(",")) break;
    }
  }
  if (!at("{")) {
    if (name.empty()) fail(peek(), "expected a name or '{' after '" + kw.text + "'");
    // struct foo; alone declares it here; anything else refers to it.
    const bool decl_only = at(";") && !s.is_typedef;
    return tag_reference(name, Kind::Aggregate, agg, name_tok, decl_only);
  }
  // A definition.
  TypeId node;
  const std::string key = name.empty() ? std::string() : qualify(name);
  if (!name.empty()) {
    auto it = tags_.find(key);
    if (it != tags_.end() && it->second.defined && !it->second.existing) {
      ctx_.error(name_tok, "redefinition of '" + kw.text + " " + name + "'");
      node = g_.reserve();  // parsed and dropped
    } else if (it != tags_.end() && !it->second.defined && it->second.id.is_local() && !g_.is_set(it->second.id)) {
      node = it->second.id;
      it->second.defined = true;
      it->second.agg = agg;
    } else {
      node = g_.reserve();
      tags_[key] = Tag{node, Kind::Aggregate, agg, true, false, name_tok.file, name_tok.line};
    }
    if (cpp_) syms_[key] = Sym{Sym::Kind::Typedef, node, {}};
  } else {
    node = g_.reserve();
  }
  next();  // {
  std::vector<Member> members;
  bool has_virtual = false;
  for (TypeId b : bases) {
    Member m;
    m.type = b;
    m.where = name_tok;
    members.push_back(m);
  }
  if (cpp_) scope_.push_back(name.empty() ? std::string() : name);
  ++nesting_;
  struct Pop {
    Parser &p;
    bool cpp;
    ~Pop() {
      --p.nesting_;
      if (cpp && !p.scope_.empty()) p.scope_.pop_back();
    }
  } pop{*this, cpp_};
  ctx_.check_nesting(nesting_);
  while (!at("}")) {
    if (at_eof()) fail(peek(), "expected '}' at end of input");
    try {
      member_declaration(members, name, has_virtual);
    } catch (const ParseError &e) {
      ctx_.error(e.at, e.message);
      // Recover inside the body: to the next ';' or the closing brace.
      for (;;) {
        const Token t = peek();
        if (t.kind == TK::Eof || t.punct("}")) break;
        if (t.punct("{") || t.punct("(") || t.punct("[")) {
          skip_balanced();
          continue;
        }
        next();
        if (t.punct(";")) break;
      }
    }
  }
  next();  // }
  attrs.merge(attributes());
  if (has_virtual && bases.empty()) {
    Member vptr;
    vptr.name = "_vptr." + name;
    vptr.type = pointer_to(pointer_to(add(FunctionType{int_type(rules_.int_size, true, IntRank::Int), {}, true, CallConv::Default})));
    vptr.where = name_tok;
    members.insert(members.begin(), vptr);
  }
  AggregateType a;
  a.kind = agg;
  a.name = key;
  std::uint32_t align = 1;
  layout(a, members, attrs, pack_, align);
  if (cpp_ && members.empty() && a.size == 0) a.size = 1;
  local_align_[node.raw()] = align;
  g_.set(node, a);
  local_aggregates_.push_back({node, rules_.pointer_size});
  s.defined_tag = true;
  s.anonymous_tag = name.empty();
  if (!key.empty()) {
    const std::string nkey = std::string(agg == AggregateKind::Union ? "union " : agg == AggregateKind::Class ? "class " : "struct ") + key;
    if (!named_index_.contains(nkey)) {
      named_index_[nkey] = named_.size();
      named_.push_back({nkey, node, name_tok.file, name_tok.line});
    }
  }
  return node;
}

void Parser::member_declaration(std::vector<Member> &members, const std::string &class_name, bool &has_virtual) {
  if (accept(";")) return;
  const Token &t = peek();
  if (t.ident("_Static_assert") || t.ident("static_assert")) return static_assert_decl();
  if (cpp_) {
    if ((t.ident("public") || t.ident("private") || t.ident("protected")) && peek(1).punct(":")) {
      next();
      next();
      return;
    }
    if (t.ident("template")) return template_decl();
    if (t.ident("using")) return using_decl();
    if (t.ident("friend")) {
      skip_to_semicolon();
      return;
    }
    // A constructor or destructor.
    if ((t.punct("~") && peek(1).kind == TK::Ident) ||
        (t.kind == TK::Ident && t.text == class_name && peek(1).punct("(")) ||
        ((t.ident("explicit") || t.ident("inline") || t.ident("constexpr") || t.ident("virtual")) &&
         ((peek(1).kind == TK::Ident && peek(1).text == class_name && peek(2).punct("(")) || peek(1).punct("~")))) {
      if (t.ident("virtual") || (t.punct("~") && false)) has_virtual = true;
      while (!at_eof() && !at("(")) next();
      skip_balanced();
      while (!at_eof() && !at(";") && !at("{")) {
        if (at("(")) skip_balanced();
        else next();
      }
      if (at("{")) {
        skip_balanced();
        accept(";");
      } else {
        next();
      }
      return;
    }
  }
  Specs s = decl_specs(true);
  if (s.is_virtual) has_virtual = true;
  if (accept(";")) {
    // An anonymous struct or union member (C11), or a nested type's definition.
    // A name the lookup gave for an anonymous struct or union itself (a
    // type by hash, docs/cparse.md) declares an anonymous member too.
    bool anonymous_ref = false;
    if (s.named && s.typedef_name && !s.defined_tag) {
      const Type *t = peek_type(*s.named);
      if (const auto *q = t ? t->as<QualifiedType>() : nullptr) t = peek_type(q->target);
      const auto *a = t ? t->as<AggregateType>() : nullptr;
      anonymous_ref = a && a->name.empty();
    }
    if (s.named && ((s.defined_tag && s.anonymous_tag) || anonymous_ref) && !s.is_typedef) {
      Member m;
      m.type = qualified(*s.named, s.quals);
      m.where = s.where;
      members.push_back(m);
    }
    return;
  }
  if (!s.any_type() && !s.quals) fail(peek(), "expected a member declaration before '" + peek().text + "'");
  for (;;) {
    Member m;
    m.where = peek();
    Declarator d;
    if (!at(":")) d = declarator(true);
    TypeId base = specs_type(s);
    if (d.attrs.mode) base = sized_int_for_mode(base, d.attrs.mode, d.where);
    if (d.attrs.vector_size) {
      std::uint64_t es = size_of(base);
      if (es) {
        base = add(ArrayType{base, d.attrs.vector_size / es});
        vector_ids_.insert(base.raw());
      }
    }
    const bool is_func = !d.ops.empty() && d.ops.back().kind == DeclOp::Kind::Func;
    TypeId ty = apply(base, d, false, d.attrs.cc ? d.attrs.cc : s.attrs.cc);
    if (accept(":")) {
      Value w = const_expr();
      if (w.v < 0 || w.v > 128) fail(m.where, "invalid bitfield width");
      m.width = static_cast<std::uint32_t>(w.v);
    }
    Attrs after = attributes();
    m.attrs = s.attrs;
    m.attrs.merge(d.attrs);
    m.attrs.merge(after);
    if (s.is_typedef) {
      define_typedef(d.name, ty, d.where, m.attrs);
    } else if (is_func) {
      // A method: its body or = 0 / default / delete.
      if (at("{")) {
        skip_balanced();
        return;
      }
      if (accept("=")) skip_initializer();
    } else if (s.is_static || s.is_constexpr) {
      if (accept("=")) skip_initializer();
      else if (at("{")) skip_balanced();
    } else {
      if (d.name.empty() && !m.width) fail(m.where, "a member needs a name");
      if (!m.width || *m.width) {
        if (!complete(ty)) {
          const Type *st = peek_type(strip(ty));
          const auto *arr = st ? st->as<ArrayType>() : nullptr;
          if (!(arr && arr->count == 0 && complete(arr->element)))
            fail(m.where, "field '" + d.name + "' has incomplete type");
        }
      }
      if (m.width) {
        const Type *st = peek_type(strip(ty));
        if (!st || !(st->as<IntType>() || st->as<EnumType>() || st->as<BoolType>()))
          fail(m.where, "bitfield '" + d.name + "' has a non-integral type");
        if (*m.width > size_of(ty) * 8) fail(m.where, "width of bitfield '" + d.name + "' exceeds its type");
      }
      m.name = d.name;
      m.type = ty;
      if (accept("=")) skip_initializer();  // C++ default member initializer
      else if (cpp_ && at("{")) skip_balanced();
      members.push_back(std::move(m));
      if (members.size() > 1'000'000) fail(peek(), "too many members");
    }
    if (accept(",")) continue;
    expect(";");
    return;
  }
}

void Parser::layout(AggregateType &agg, std::vector<Member> &members, const Attrs &attrs, std::uint32_t pack,
                    std::uint32_t &align_out) {
  const bool msvc = rules_.bitfields == BitfieldModel::Msvc;
  const bool is_union = agg.kind == AggregateKind::Union;
  std::uint64_t bits = 0, size_bits = 0;
  std::uint32_t align = 1;
  // MSVC: the storage unit the current run of bitfields uses.
  bool in_unit = false;
  std::uint64_t unit_start = 0, unit_bits = 0, unit_used = 0;
  auto close_unit = [&] {
    if (in_unit) {
      bits = unit_start + unit_bits;
      in_unit = false;
    }
  };
  for (Member &m : members) {
    const std::uint64_t size = size_of(m.type);
    const std::uint32_t talign = align_of(m.type);
    std::uint32_t a = talign;
    if (m.attrs.aligned) a = std::max(a, m.attrs.aligned);
    else if (attrs.packed || m.attrs.packed) a = 1;
    if (pack && !m.attrs.aligned) a = std::min(a, pack);
    if (rules_.max_alignment) a = std::min(a, rules_.max_alignment);
    Field f;
    f.name = m.name;
    f.type = m.type;
    if (m.width) {
      const std::uint32_t w = *m.width;
      if (is_union) {
        if (w == 0) continue;
        f.bit_offset = 0;
        f.bit_size = w;
        size_bits = std::max<std::uint64_t>(size_bits, align_up(w, 8));
        if (!m.name.empty() || msvc) align = std::max(align, a);
        if (!m.name.empty()) agg.fields.push_back(std::move(f));  // compilers record no unnamed bitfields
        continue;
      }
      if (msvc) {
        if (w == 0) {
          close_unit();
          continue;
        }
        // GCC's and clang's ms_struct layout (mingw) keeps a bitfield's
        // storage unit aligned in a packed struct; Microsoft's own packs it.
        if (ctx_.options.profile.compiler != Compiler::Msvc && (attrs.packed || m.attrs.packed) && !m.attrs.aligned)
          a = pack ? std::min(talign, pack) : talign;
        if (in_unit && unit_bits == size * 8 && unit_used + w <= unit_bits) {
          f.bit_offset = unit_start + unit_used;
          unit_used += w;
        } else {
          close_unit();
          bits = align_up(align_up(bits, 8), std::uint64_t(a) * 8);
          in_unit = true;
          unit_start = bits;
          unit_bits = size * 8;
          unit_used = w;
          f.bit_offset = bits;
        }
        f.bit_size = w;
        align = std::max(align, a);
        if (!m.name.empty()) agg.fields.push_back(std::move(f));
        continue;
      }
      // GCC (PCC_BITFIELD_TYPE_MATTERS).
      if (w == 0) {
        const std::uint32_t za = pack ? std::min(talign, pack) : talign;
        bits = align_up(bits, std::uint64_t(za) * 8);
        if (rules_.zero_width_bitfield_aligns) align = std::max(align, za);
        continue;
      }
      if (!attrs.packed && !m.attrs.packed && !pack) {
        const std::uint64_t ab = std::uint64_t(talign) * 8;
        const std::uint64_t off = bits % ab;
        if ((off + w + ab - 1) / ab > (size * 8) / ab) bits = align_up(bits, ab);
      }
      f.bit_offset = bits;
      f.bit_size = w;
      bits += w;
      if (!m.name.empty()) {
        align = std::max(align, a);
        agg.fields.push_back(std::move(f));
      }
      continue;
    }
    if (msvc) close_unit();
    if (is_union) {
      f.bit_offset = 0;
      size_bits = std::max<std::uint64_t>(size_bits, size * 8);
    } else {
      bits = align_up(align_up(bits, 8), std::uint64_t(a) * 8);
      f.bit_offset = bits;
      bits += size * 8;
    }
    align = std::max(align, a);
    agg.fields.push_back(std::move(f));
  }
  if (msvc) close_unit();
  if (attrs.aligned) align = std::max(align, attrs.aligned);
  if (rules_.max_alignment) align = std::min(align, rules_.max_alignment);
  const std::uint64_t used = is_union ? size_bits : bits;
  agg.size = align_up(align_up(used, 8) / 8, align);
  if (attrs.aligned) agg.alignment = attrs.aligned;
  agg.complete = true;
  align_out = align;
}

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

TypeId Parser::enum_spec(const Token &kw, Specs &s) {
  bool scoped = false;
  if (cpp_ && (peek().ident("class") || peek().ident("struct"))) {
    next();
    scoped = true;
  }
  Attrs attrs = attributes();
  std::string name;
  Token name_tok = kw;
  if (peek().kind == TK::Ident && !is_keyword(peek().text)) {
    name_tok = next();
    name = name_tok.text;
  }
  attrs.merge(attributes());
  std::optional<TypeId> fixed;
  if (at(":") && !peek(1).punct(":")) {
    next();
    fixed = type_name();
  }
  if (!at("{")) {
    if (name.empty()) fail(peek(), "expected a name or '{' after 'enum'");
    TypeId id = tag_reference(name, Kind::Enum, AggregateKind::Struct, name_tok, at(";") && !s.is_typedef);
    // enum E : T; is a complete opaque declaration.
    if (fixed && id.is_local() && !g_.is_set(id)) {
      EnumType e;
      e.name = qualify(name);
      e.size = static_cast<std::uint32_t>(size_of(*fixed));
      const Type *ft = peek_type(strip(*fixed));
      e.is_signed = ft && ft->as<IntType>() && ft->as<IntType>()->is_signed;
      g_.set(id, e);
      tags_[qualify(name)].defined = true;
    }
    return id;
  }
  TypeId node;
  const std::string key = name.empty() ? std::string() : qualify(name);
  if (!name.empty()) {
    auto it = tags_.find(key);
    if (it != tags_.end() && it->second.defined && !it->second.existing) {
      ctx_.error(name_tok, "redefinition of 'enum " + name + "'");
      node = g_.reserve();
    } else if (it != tags_.end() && !it->second.defined && it->second.id.is_local() && !g_.is_set(it->second.id)) {
      node = it->second.id;
      it->second.defined = true;
    } else {
      node = g_.reserve();
      tags_[key] = Tag{node, Kind::Enum, AggregateKind::Struct, true, false, name_tok.file, name_tok.line};
    }
    if (cpp_) syms_[key] = Sym{Sym::Kind::Typedef, node, {}};
  } else {
    node = g_.reserve();
  }
  next();  // {
  EnumType e;
  e.name = key;
  std::int64_t next_value = 0;
  bool any_negative = false;
  std::int64_t lo = 0, hi = 0;
  bool first = true;
  bool any_unsigned_big = false;
  while (!accept("}")) {
    Token n = next();
    if (n.kind != TK::Ident) fail(n, "expected an enumerator name");
    attributes();
    Value v{next_value, false, 4};
    if (accept("=")) v = const_expr();
    std::int64_t value = v.v;
    if (v.is_unsigned && v.size == 8 && value < 0) any_unsigned_big = true;
    e.values.push_back({n.text, value});
    if (e.values.size() > 1'000'000) fail(n, "too many enumerators");
    if (value < 0 && !(v.is_unsigned && v.size == 8)) any_negative = true;
    if (first || value < lo) lo = value;
    if (first || value > hi) hi = value;
    first = false;
    const std::string cname = scoped ? key + "::" + n.text : qualify(n.text);
    syms_[cname] = Sym{Sym::Kind::EnumConst, node, Value{value, v.is_unsigned, v.size}};
    next_value = value + 1;
    if (!accept(",")) {
      expect("}");
      break;
    }
  }
  attrs.merge(attributes());
  if (fixed) {
    e.size = static_cast<std::uint32_t>(std::max<std::uint64_t>(1, size_of(*fixed)));
    const Type *ft = peek_type(strip(*fixed));
    e.is_signed = ft && ((ft->as<IntType>() && ft->as<IntType>()->is_signed));
  } else if (scoped) {
    e.size = rules_.int_size;
    e.is_signed = true;
  } else if (rules_.msvc_enums) {
    e.size = rules_.int_size;
    e.is_signed = true;
  } else {
    e.is_signed = any_negative;
    auto fits = [&](std::uint32_t bytes) {
      if (bytes >= 8) return true;
      if (any_unsigned_big) return false;
      const std::int64_t bitsz = std::int64_t(bytes) * 8;
      if (e.is_signed) return lo >= -(std::int64_t(1) << (bitsz - 1)) && hi < (std::int64_t(1) << (bitsz - 1));
      return hi < (std::int64_t(1) << bitsz);
    };
    if (attrs.packed) {
      e.size = fits(1) ? 1 : fits(2) ? 2 : fits(4) ? 4 : 8;
    } else {
      e.size = fits(rules_.int_size) ? rules_.int_size : 8;
    }
    if (attrs.mode) e.size = attrs.mode;
  }
  g_.set(node, e);
  s.defined_tag = true;
  s.anonymous_tag = name.empty();
  if (!key.empty() && !named_index_.contains("enum " + key)) {
    named_index_["enum " + key] = named_.size();
    named_.push_back({"enum " + key, node, name_tok.file, name_tok.line});
  }
  return node;
}

// ---------------------------------------------------------------------------
// Constant expressions
// ---------------------------------------------------------------------------

Value Parser::wrap(Value v) const {
  if (v.size < 4) v.size = 4;
  if (v.size == 4) {
    if (v.is_unsigned) v.v = std::int64_t(std::uint32_t(std::uint64_t(v.v)));
    else v.v = std::int64_t(std::int32_t(std::uint32_t(std::uint64_t(v.v))));
  }
  return v;
}

Value Parser::const_expr(int depth) { return conditional(depth); }

Value Parser::conditional(int depth) {
  ctx_.check_nesting(static_cast<std::uint32_t>(depth));
  Value c = binary(1, depth);
  if (accept("?")) {
    Value a = at(":") ? c : conditional(depth + 1);  // GNU a ?: b
    expect(":");
    Value b = conditional(depth + 1);
    Value r = c.v ? a : b;
    r.is_unsigned = a.is_unsigned || b.is_unsigned;
    r.size = std::max(a.size, b.size);
    return wrap(r);
  }
  return c;
}

namespace {
int binary_prec(const Token &k) {
  if (k.kind != TK::Punct) return -1;
  const std::string &s = k.text;
  if (s == "*" || s == "/" || s == "%") return 10;
  if (s == "+" || s == "-") return 9;
  if (s == "<<" || s == ">>") return 8;
  if (s == "<" || s == ">" || s == "<=" || s == ">=") return 7;
  if (s == "==" || s == "!=") return 6;
  if (s == "&") return 5;
  if (s == "^") return 4;
  if (s == "|") return 3;
  if (s == "&&") return 2;
  if (s == "||") return 1;
  return -1;
}
}  // namespace

Value Parser::binary(int min_prec, int depth) {
  ctx_.check_nesting(static_cast<std::uint32_t>(depth));
  Value lhs = unary(depth + 1);
  for (;;) {
    const Token &op = peek();
    const int p = binary_prec(op);
    if (p < min_prec) return lhs;
    Token o = next();
    Value rhs = binary(p + 1, depth + 1);
    const bool shift = o.text == "<<" || o.text == ">>";
    Value r;
    r.size = shift ? lhs.size : std::max(lhs.size, rhs.size);
    r.is_unsigned = shift ? lhs.is_unsigned
                          : (lhs.is_unsigned && lhs.size >= rhs.size) || (rhs.is_unsigned && rhs.size >= lhs.size);
    const auto ul = std::uint64_t(lhs.v), ur = std::uint64_t(rhs.v);
    const std::string &s = o.text;
    auto cmp = [&](bool b) {
      r = {b ? 1 : 0, false, 4};
    };
    if (s == "*") r.v = std::int64_t(ul * ur);
    else if (s == "/" || s == "%") {
      if (rhs.v == 0) fail(o, "division by zero in a constant expression");
      if (r.is_unsigned) {
        std::uint64_t a = r.size == 4 ? std::uint32_t(ul) : ul, b = r.size == 4 ? std::uint32_t(ur) : ur;
        r.v = std::int64_t(s == "/" ? a / b : a % b);
      } else if (lhs.v == std::numeric_limits<std::int64_t>::min() && rhs.v == -1) {
        r.v = s == "/" ? lhs.v : 0;
      } else {
        r.v = s == "/" ? lhs.v / rhs.v : lhs.v % rhs.v;
      }
    } else if (s == "+") r.v = std::int64_t(ul + ur);
    else if (s == "-") r.v = std::int64_t(ul - ur);
    else if (s == "<<") r.v = ur >= 64 ? 0 : std::int64_t(ul << ur);
    else if (s == ">>") {
      if (ur >= 64) r.v = lhs.is_unsigned || lhs.v >= 0 ? 0 : -1;
      else if (lhs.is_unsigned) r.v = std::int64_t((lhs.size == 4 ? std::uint32_t(ul) : ul) >> ur);
      else r.v = lhs.v >> ur;
    } else if (s == "==") cmp(wrap(lhs).v == wrap(rhs).v);
    else if (s == "!=") cmp(wrap(lhs).v != wrap(rhs).v);
    else if (s == "<" || s == ">" || s == "<=" || s == ">=") {
      bool b;
      if (r.is_unsigned) {
        std::uint64_t a = std::uint64_t(lhs.v), c = std::uint64_t(rhs.v);
        if (r.size == 4) {
          a = std::uint32_t(a);
          c = std::uint32_t(c);
        }
        b = s == "<" ? a < c : s == ">" ? a > c : s == "<=" ? a <= c : a >= c;
      } else {
        b = s == "<" ? lhs.v < rhs.v : s == ">" ? lhs.v > rhs.v : s == "<=" ? lhs.v <= rhs.v : lhs.v >= rhs.v;
      }
      cmp(b);
    } else if (s == "&") r.v = lhs.v & rhs.v;
    else if (s == "^") r.v = lhs.v ^ rhs.v;
    else if (s == "|") r.v = lhs.v | rhs.v;
    else if (s == "&&") cmp(lhs.v && rhs.v);
    else if (s == "||") cmp(lhs.v || rhs.v);
    lhs = wrap(r);
  }
}

Value Parser::cast_value(Value v, TypeId to) {
  const Type *t = peek_type(strip(to));
  if (!t) return v;
  std::uint64_t size = 0;
  bool is_signed = true;
  if (const auto *i = t->as<IntType>()) {
    size = i->size;
    is_signed = i->is_signed;
  } else if (const auto *e = t->as<EnumType>()) {
    size = e->size;
    is_signed = e->is_signed;
  } else if (const auto *b = t->as<BoolType>()) {
    (void)b;
    return Value{v.v != 0, false, 4};
  } else if (const auto *p = t->as<PointerType>()) {
    size = p->size;
    is_signed = false;
  } else if (t->as<VoidType>()) {
    return v;
  } else {
    fail(peek(), "a cast to a non-scalar type in a constant expression");
  }
  std::uint64_t u = std::uint64_t(v.v);
  if (size < 8) {
    const std::uint64_t mask = (std::uint64_t(1) << (size * 8)) - 1;
    u &= mask;
    if (is_signed && (u >> (size * 8 - 1)) & 1) u |= ~mask;
  }
  return Value{std::int64_t(u), !is_signed, std::uint8_t(std::max<std::uint64_t>(4, std::min<std::uint64_t>(size, 8)))};
}

Value Parser::unary(int depth) {
  ctx_.check_nesting(static_cast<std::uint32_t>(depth));
  const Token &t = peek();
  if (t.punct("-") || t.punct("+") || t.punct("~") || t.punct("!")) {
    Token o = next();
    Value v = unary(depth + 1);
    if (o.text == "-") v.v = std::int64_t(~std::uint64_t(v.v) + 1);
    else if (o.text == "~") v.v = ~v.v;
    else if (o.text == "!") v = {v.v == 0, false, 4};
    return wrap(v);
  }
  if (t.ident("sizeof")) {
    Token kw = next();
    TypeId ty;
    if (at("(") && starts_type_name(1)) {
      next();
      ty = type_name();
      expect(")");
    } else {
      std::optional<TypeId> e = expr_type(depth + 1);
      if (!e) fail(kw, "sizeof of an expression revkit can't type");
      ty = *e;
    }
    if (!complete(ty)) {
      const Type *st = peek_type(strip(ty));
      if (!(st && st->as<VoidType>())) fail(kw, "sizeof of an incomplete type");
      return Value{1, true, std::uint8_t(rules_.pointer_size)};  // GNU: sizeof(void) == 1
    }
    return Value{std::int64_t(size_of(ty)), true, std::uint8_t(rules_.pointer_size)};
  }
  if (t.ident("_Alignof") || t.ident("__alignof__") || t.ident("__alignof") || t.ident("alignof")) {
    Token kw = next();
    TypeId ty;
    if (at("(") && starts_type_name(1)) {
      next();
      ty = type_name();
      expect(")");
    } else {
      std::optional<TypeId> e = expr_type(depth + 1);
      if (!e) fail(kw, "alignof of an expression revkit can't type");
      ty = *e;
    }
    return Value{std::int64_t(align_of(ty)), true, std::uint8_t(rules_.pointer_size)};
  }
  // A cast.
  if (t.punct("(") && starts_type_name(1)) {
    next();
    TypeId ty = type_name();
    expect(")");
    if (at("{")) fail(peek(), "a compound literal is not a constant");
    return cast_value(unary(depth + 1), ty);
  }
  return primary(depth + 1);
}

Value Parser::offsetof_expr(int depth) {
  expect("(");
  TypeId ty = type_name();
  expect(",");
  std::uint64_t bits = 0;
  TypeId cur = ty;
  bool first = true;
  for (;;) {
    if (first || accept(".")) {
      Token n = next();
      if (n.kind != TK::Ident) fail(n, "expected a member name in offsetof");
      // Find the member, looking through anonymous members.
      std::function<bool(TypeId, std::uint64_t)> find = [&](TypeId agg, std::uint64_t base) -> bool {
        const Type *at = peek_type(strip(agg));
        const auto *a = at ? at->as<AggregateType>() : nullptr;
        if (!a) return false;
        for (const Field &f : a->fields) {
          if (f.name == n.text) {
            if (f.bit_size) fail(n, "offsetof a bitfield");
            bits = base + f.bit_offset;
            cur = f.type;
            return true;
          }
          if (f.name.empty() && find(f.type, base + f.bit_offset)) return true;
        }
        return false;
      };
      if (!find(cur, bits)) fail(n, "no member named '" + n.text + "' in offsetof");
      first = false;
      continue;
    }
    if (accept("[")) {
      Value idx = const_expr(depth + 1);
      expect("]");
      const Type *at = peek_type(strip(cur));
      const auto *arr = at ? at->as<ArrayType>() : nullptr;
      if (!arr) fail(peek(), "subscript of a non-array in offsetof");
      bits += std::uint64_t(idx.v) * size_of(arr->element) * 8;
      cur = arr->element;
      continue;
    }
    break;
  }
  expect(")");
  return Value{std::int64_t(bits / 8), true, std::uint8_t(rules_.pointer_size)};
}

Value Parser::primary(int depth) {
  Token t = next();
  if (t.punct("(")) {
    Value v = const_expr(depth + 1);
    while (accept(",")) v = const_expr(depth + 1);
    expect(")");
    return v;
  }
  if (t.kind == TK::Number) {
    IntLiteral l = parse_int_literal(t.text);
    if (!l.ok) fail(t, "invalid number '" + t.text + "'");
    if (l.is_float) fail(t, "a floating constant in an integer constant expression");
    Value v;
    v.v = std::int64_t(l.value);
    const bool decimal = !(t.text.size() > 1 && t.text[0] == '0');
    const std::uint64_t imax = 0x7fffffff, umax = 0xffffffff;
    if (l.longs == 0 && !l.is_unsigned && l.value <= imax) v = {v.v, false, 4};
    else if (l.longs == 0 && l.is_unsigned && l.value <= umax) v = {v.v, true, 4};
    else if (l.longs == 0 && !decimal && l.value <= umax) v = {v.v, true, 4};
    else v = {v.v, l.is_unsigned, 8};
    if (l.longs == 1 && rules_.long_size == 4 && l.value <= (l.is_unsigned ? umax : imax)) v.size = 4;
    return v;
  }
  if (t.kind == TK::Char) {
    std::int64_t c;
    if (!char_value(t.text, c)) fail(t, "invalid character constant");
    return Value{c, false, 4};
  }
  if (t.kind == TK::Ident) {
    if (t.text == "__builtin_offsetof" || t.text == "offsetof") return offsetof_expr(depth);
    if (t.text == "true") return Value{1, false, 4};
    if (t.text == "false" || t.text == "nullptr") return Value{0, false, 4};
    if (t.text == "__builtin_constant_p") {
      if (at("(")) skip_balanced();
      return Value{0, false, 4};
    }
    if (const Sym *s = find_sym(t.text); s && s->kind == Sym::Kind::EnumConst) return s->value;
    // C++ A::B enumerators.
    if (cpp_ && at("::")) {
      std::string q = t.text;
      while (accept("::")) q += "::" + next().text;
      if (const Sym *s = find_sym(q); s && s->kind == Sym::Kind::EnumConst) return s->value;
    }
    fail(t, "'" + t.text + "' is not a constant");
  }
  fail(t, t.kind == TK::Eof ? "expected an expression at end of input" : "expected an expression before '" + t.text + "'");
}

std::optional<TypeId> Parser::expr_type(int depth) {
  ctx_.check_nesting(static_cast<std::uint32_t>(depth));
  // Unary operators and casts.
  if (accept("*")) {
    auto t = expr_type(depth + 1);
    if (!t) return std::nullopt;
    const Type *x = peek_type(strip(*t));
    if (const auto *p = x ? x->as<PointerType>() : nullptr) return p->target;
    if (const auto *a = x ? x->as<ArrayType>() : nullptr) return a->element;
    return std::nullopt;
  }
  if (accept("&")) {
    auto t = expr_type(depth + 1);
    return t ? std::optional<TypeId>(pointer_to(*t)) : std::nullopt;
  }
  std::optional<TypeId> cur;
  if (at("(") && starts_type_name(1)) {
    next();
    TypeId ty = type_name();
    expect(")");
    if (!expr_type(depth + 1)) {
      // The operand needn't be typeable: ((T *)0)->m
    }
    cur = ty;
  } else if (accept("(")) {
    cur = expr_type(depth + 1);
    if (!cur) return std::nullopt;
    expect(")");
  } else {
    const Token &t = peek();
    if (t.kind == TK::String) {
      std::size_t n = 0;
      while (peek().kind == TK::String) n += string_value(next().text).size();
      cur = add(ArrayType{plain_char(), n + 1});
    } else if (t.kind == TK::Number) {
      IntLiteral l = parse_int_literal(next().text);
      if (l.is_float) cur = store_.float_type(rules_.double_size, FloatKind::Double);
      else cur = int_type(l.longs == 2 ? rules_.long_long_size : l.longs ? rules_.long_size : rules_.int_size,
                          !l.is_unsigned, l.longs == 2 ? IntRank::LongLong : l.longs ? IntRank::Long : IntRank::Int);
    } else if (t.kind == TK::Ident) {
      const Sym *s = find_sym(t.text);
      if (!s || (s->kind != Sym::Kind::Object && s->kind != Sym::Kind::Function && s->kind != Sym::Kind::EnumConst))
        return std::nullopt;
      next();
      cur = s->kind == Sym::Kind::EnumConst ? int_type(rules_.int_size, true, IntRank::Int) : s->type;
    } else {
      return std::nullopt;
    }
  }
  // Postfix: ->m, .m, [i]
  for (;;) {
    if (at("->") || at(".")) {
      const bool arrow = next().text == "->";
      Token n = next();
      TypeId base = *cur;
      if (arrow) {
        const Type *x = peek_type(strip(base));
        const auto *p = x ? x->as<PointerType>() : nullptr;
        if (!p) return std::nullopt;
        base = p->target;
      }
      std::function<std::optional<TypeId>(TypeId)> find = [&](TypeId agg) -> std::optional<TypeId> {
        const Type *at = peek_type(strip(agg));
        const auto *a = at ? at->as<AggregateType>() : nullptr;
        if (!a) return std::nullopt;
        for (const Field &f : a->fields) {
          if (f.name == n.text) return f.type;
          if (f.name.empty())
            if (auto r = find(f.type)) return r;
        }
        return std::nullopt;
      };
      cur = find(base);
      if (!cur) return std::nullopt;
    } else if (at("[")) {
      skip_balanced();
      const Type *x = peek_type(strip(*cur));
      if (const auto *a = x ? x->as<ArrayType>() : nullptr) cur = a->element;
      else if (const auto *p = x ? x->as<PointerType>() : nullptr) cur = p->target;
      else return std::nullopt;
    } else {
      return cur;
    }
  }
}

std::optional<Value> Parser::eval_tokens(std::vector<Token> toks) {
  if (toks.empty()) return std::nullopt;
  std::deque<Token> saved;
  saved.swap(la_);
  replay_ = &toks;
  replay_pos_ = 0;
  const std::size_t diags = ctx_.result.diagnostics.size(), errors = ctx_.result.errors, warnings = ctx_.result.warnings;
  std::optional<Value> out;
  try {
    Value v = const_expr();
    if (at_eof()) out = v;
  } catch (const ParseError &) {
  }
  ctx_.result.diagnostics.resize(diags);
  ctx_.result.errors = errors;
  ctx_.result.warnings = warnings;
  replay_ = nullptr;
  la_.swap(saved);
  return out;
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

void Parser::finish() {
  Result &r = ctx_.result;
  // Constants: object-like macros of the sources' own files.
  std::map<std::string, std::size_t> seen;
  std::vector<Constant> constants;
  for (const DefineRecord &d : pp_.defines()) {
    if (d.file < ctx_.files.size() && (ctx_.files[d.file].system || ctx_.files[d.file].builtin)) continue;
    const Macro *m = pp_.macro(d.name);
    if (!m || m->function_like || m->body.empty() || m->file != d.file || m->line != d.line) continue;
    std::vector<Token> body;
    try {
      body = pp_.expand(m->body);
    } catch (const LimitReached &) {
      continue;
    }
    std::optional<Value> v = eval_tokens(std::move(body));
    if (!v) continue;
    Constant c;
    c.name = d.name;
    c.value = v->v;
    c.is_unsigned = v->is_unsigned;
    c.where = ctx_.location(d.file, d.line);
    if (auto it = seen.find(d.name); it != seen.end()) constants[it->second] = c;
    else {
      seen[d.name] = constants.size();
      constants.push_back(std::move(c));
    }
  }

  // Tags never defined are incomplete; any node left unset (a parse cut
  // short) is undefined.
  for (auto &[name, tag] : tags_) {
    if (tag.existing || !tag.id.is_local() || g_.is_set(tag.id)) continue;
    const std::string kw0 = tag.kind == Kind::Enum ? "enum " : tag.agg == AggregateKind::Union ? "union " : tag.agg == AggregateKind::Class ? "class " : "struct ";
    // Only declared here: the program's own definition, when it has one.
    if (auto e = existing(kw0 + name)) {
      g_.set(tag.id, store_.get(*e));
      continue;
    }
    if (tag.kind == Kind::Enum) {
      EnumType e;
      e.name = name;
      e.size = rules_.int_size;
      e.complete = false;
      g_.set(tag.id, e);
    } else {
      AggregateType a;
      a.kind = tag.agg;
      a.name = name;
      a.complete = false;
      g_.set(tag.id, a);
    }
    const std::string kw = tag.kind == Kind::Enum ? "enum " : tag.agg == AggregateKind::Union ? "union " : tag.agg == AggregateKind::Class ? "class " : "struct ";
    if (!named_index_.contains(kw + name)) {
      named_index_[kw + name] = named_.size();
      named_.push_back({kw + name, tag.id, tag.file, tag.line});
    }
  }
  for (std::uint32_t i = 0; i < g_.size(); ++i)
    if (!g_.is_set(TypeId::local(i))) g_.set(TypeId::local(i), UndefinedType{1});

  infer_packing(g_, store_, local_aggregates_);
  if (std::size_t n = g_.break_invalid_cycles())
    ctx_.diag(Severity::Warning, last_.file, last_.line, 0, std::to_string(n) + " invalid recursive type references made undefined");
  std::vector<TypeId> ids;
  try {
    ids = store_.intern(g_);
  } catch (const std::exception &e) {
    ctx_.diag(Severity::Error, last_.file, last_.line, 0, std::string("could not intern the types: ") + e.what());
    return;
  }
  auto map = [&](TypeId id) { return id.is_local() ? ids.at(id.index()) : id; };
  if (single_out_) single_out_->type = map(single_out_->type);

  for (const NamedEntry &n : named_) r.named.push_back({n.key, map(n.id), ctx_.location(n.file, n.line)});
  for (const ProtoEntry &p : protos_) {
    Prototype out;
    out.name = p.name;
    out.type = map(p.type);
    out.where = ctx_.location(p.file, p.line);
    out.defined = p.defined;
    out.asm_label = p.asm_label;
    out.noreturn = p.noreturn;
    r.prototypes.push_back(std::move(out));
  }
  r.constants = constants;
  for (auto &[k, id] : used_existing_) r.used_existing.emplace_back(k, id);
  if (ctx_.options.defines_as_enums) {
    std::map<std::string, std::vector<const Constant *>> by_file;
    for (const Constant &c : r.constants) by_file[c.where.file].push_back(&c);
    for (auto &[file, list] : by_file) {
      std::string stem = file;
      if (auto slash = stem.rfind('/'); slash != std::string::npos) stem = stem.substr(slash + 1);
      for (char &c : stem)
        if (!is_ident_char(static_cast<unsigned char>(c))) c = '_';
      if (stem.empty() || (stem[0] >= '0' && stem[0] <= '9')) stem = "_" + stem;
      EnumType e;
      e.name = stem + "_constants";
      bool neg = false, wide = false;
      for (const Constant *c : list) {
        e.values.push_back({c->name, c->value});
        if (c->value < 0 && !c->is_unsigned) neg = true;
        if (c->value > 0xffffffffLL || c->value < -0x80000000LL || (c->is_unsigned && c->value < 0)) wide = true;
      }
      e.is_signed = neg;
      e.size = wide ? 8 : 4;
      NamedType nt;
      nt.key = "enum " + e.name;
      nt.id = store_.intern(e);
      nt.where.file = file;
      nt.where.line = list.front()->where.line;
      r.constant_enums.push_back(std::move(nt));
    }
  }
}

}  // namespace revkit::cparse::detail
