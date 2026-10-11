// Debugger expressions: the parser, the evaluator and the formatter
// (expr.hh, docs/debugger.md "Expressions").
#include "revkit/debug/expr.hh"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <set>

namespace revkit::debug::expr {

using K = Type::Kind;

bool Type::is_signed() const { return kind == K::int_ || kind == K::char_ || kind == K::enum_; }
bool Type::scalar() const {
  return kind == K::bool_ || kind == K::int_ || kind == K::uint_ || kind == K::char_ || kind == K::float_ ||
         kind == K::pointer || kind == K::enum_ || (kind == K::undefined && size <= 8);
}

namespace {

std::string hexs(std::uint64_t v) {
  char buf[32];
  std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(v));
  return buf;
}

TypeP make(K kind, std::uint64_t size, std::string name) {
  auto t = std::make_shared<Type>();
  t->kind = kind;
  t->size = size;
  t->name = std::move(name);
  return t;
}

}  // namespace

TypeP integer(std::uint64_t size, bool is_signed) {
  std::string name;
  switch (size) {
    case 1: name = is_signed ? "signed char" : "unsigned char"; break;
    case 2: name = is_signed ? "short" : "unsigned short"; break;
    case 4: name = is_signed ? "int" : "unsigned int"; break;
    case 8: name = is_signed ? "long long" : "unsigned long long"; break;
    default: name = (is_signed ? "int" : "uint") + std::to_string(size * 8) + "_t";
  }
  return make(is_signed ? K::int_ : K::uint_, size, name);
}

TypeP undefined(std::uint64_t size) { return make(K::undefined, size, size == 1 ? "undefined" : "undefined" + std::to_string(size)); }

TypeP pointer_to(TypeP target, unsigned pointer_size) {
  auto t = std::make_shared<Type>();
  t->kind = K::pointer;
  t->size = pointer_size;
  const std::string n = target ? target->name : "void";
  t->name = n + (n.ends_with("*") ? "*" : " *");
  t->target = std::move(target);
  return t;
}

TypeP builtin(const std::string &raw, unsigned ps) {
  // Normalize the words: "unsigned   int" -> "unsigned int".
  std::string name;
  std::string word;
  std::vector<std::string> words;
  for (char c : raw + " ") {
    if (std::isspace(static_cast<unsigned char>(c))) {
      if (!word.empty() && word != "const" && word != "volatile") words.push_back(word);
      word.clear();
    } else {
      word += c;
    }
  }
  if (words.empty()) return nullptr;
  for (const auto &w : words) name += (name.empty() ? "" : " ") + w;
  const unsigned long_size = ps == 8 ? 8 : 4;
  static const std::set<std::string> c_words = {"unsigned", "signed", "short", "long", "int", "char"};
  if (std::all_of(words.begin(), words.end(), [](const std::string &w) { return c_words.count(w) != 0; })) {
    bool uns = false, sgn = false, chr = false;
    int longs = 0, shorts = 0;
    for (const auto &w : words) {
      if (w == "unsigned") uns = true;
      if (w == "signed") sgn = true;
      if (w == "long") ++longs;
      if (w == "short") ++shorts;
      if (w == "char") chr = true;
    }
    if (chr) {
      if (longs || shorts) return nullptr;
      return uns ? make(K::uint_, 1, "unsigned char") : sgn ? make(K::int_, 1, "signed char") : make(K::char_, 1, "char");
    }
    std::uint64_t size = shorts ? 2 : longs == 1 ? long_size : longs >= 2 ? 8 : 4;
    auto t = integer(size, !uns);
    auto c = std::make_shared<Type>(*t);
    c->name = name;
    return c;
  }
  static const std::map<std::string, std::pair<int, std::uint64_t>> fixed = {
      {"int8_t", {1, 1}},   {"int16_t", {1, 2}},  {"int32_t", {1, 4}},  {"int64_t", {1, 8}},
      {"uint8_t", {0, 1}},  {"uint16_t", {0, 2}}, {"uint32_t", {0, 4}}, {"uint64_t", {0, 8}},
      {"byte", {0, 1}},     {"word", {0, 2}},     {"dword", {0, 4}},    {"qword", {0, 8}},
      {"uchar", {0, 1}},    {"ushort", {0, 2}},   {"uint", {0, 4}},     {"ulonglong", {0, 8}},
      {"longlong", {1, 8}}, {"sbyte", {1, 1}},    {"sdword", {1, 4}},   {"sqword", {1, 8}}};
  if (auto it = fixed.find(name); it != fixed.end()) {
    auto c = std::make_shared<Type>(*integer(it->second.second, it->second.first == 1));
    c->name = name;
    return c;
  }
  if (name == "size_t" || name == "uintptr_t" || name == "ulong") {
    auto c = std::make_shared<Type>(*integer(name == "ulong" ? long_size : ps, false));
    c->name = name;
    return c;
  }
  if (name == "ssize_t" || name == "intptr_t" || name == "ptrdiff_t") {
    auto c = std::make_shared<Type>(*integer(ps, true));
    c->name = name;
    return c;
  }
  if (name == "void") return make(K::void_, 0, "void");
  if (name == "bool" || name == "_Bool") return make(K::bool_, 1, name);
  if (name == "float") return make(K::float_, 4, "float");
  if (name == "double") return make(K::float_, 8, "double");
  if (name == "undefined") return undefined(1);
  if (name.rfind("undefined", 0) == 0) {
    const std::string n = name.substr(9);
    if (n == "1" || n == "2" || n == "4" || n == "8") return undefined(std::stoull(n));
  }
  if (name == "pointer") return pointer_to(nullptr, ps);
  return nullptr;
}

TypeP resolve_type_name(const std::string &name, Context &ctx) {
  if (ctx.types)
    if (auto t = ctx.types->by_name(name)) return t;
  return builtin(name, ctx.pointer_size);
}

// --- Bytes ---

namespace {

std::uint64_t to_u64(std::span<const std::uint8_t> b, bool big) {
  std::uint64_t v = 0;
  const std::size_t n = std::min<std::size_t>(b.size(), 8);
  for (std::size_t i = 0; i < n; ++i) {
    const std::size_t at = big ? i : n - 1 - i;
    v = (v << 8) | b[at];
  }
  return v;
}

std::vector<std::uint8_t> from_u64(std::uint64_t v, std::uint64_t size, bool big) {
  std::vector<std::uint8_t> out(static_cast<std::size_t>(size), 0);
  for (std::size_t i = 0; i < out.size() && i < 8; ++i) {
    const std::uint8_t byte = static_cast<std::uint8_t>(v >> (8 * i));
    out[big ? out.size() - 1 - i : i] = byte;
  }
  return out;
}

std::int64_t sign_extend(std::uint64_t v, std::uint64_t size) {
  if (size >= 8 || size == 0) return static_cast<std::int64_t>(v);
  const unsigned bits = static_cast<unsigned>(size * 8);
  const std::uint64_t m = 1ull << (bits - 1);
  v &= (1ull << bits) - 1;
  return static_cast<std::int64_t>((v ^ m) - m);
}

}  // namespace

std::uint64_t as_u64(const Value &v, bool big_endian) { return to_u64(v.bytes, big_endian); }

// --- Tokens and parsing ---

struct Node {
  enum class Op : std::uint8_t { num, flt, ident, reg, unary, binary, cast, sizeof_type, index, member, arrow, and_, or_, cond };
  Op op = Op::num;
  std::uint64_t num = 0;
  bool num_unsigned = false, num_long = false;
  double flt = 0;
  std::string name;  // ident/reg names, operators, member names, cast type names
  int stars = 0;     // cast: pointer levels
  NodeP a, b, c;
  std::size_t at = 0;
};

namespace {

struct Tok {
  enum class T : std::uint8_t { end, num, flt, chr, ident, reg, op };
  T t = T::end;
  std::string s;
  std::uint64_t num = 0;
  bool uns = false, lng = false;
  double flt = 0;
  std::size_t at = 0;
};

std::vector<Tok> lex(const std::string &s) {
  std::vector<Tok> out;
  std::size_t i = 0;
  auto ident_char = [](char c) { return std::isalnum(static_cast<unsigned char>(c)) || c == '_'; };
  while (i < s.size()) {
    const char c = s[i];
    if (std::isspace(static_cast<unsigned char>(c))) {
      ++i;
      continue;
    }
    Tok t;
    t.at = i;
    if (std::isdigit(static_cast<unsigned char>(c)) ||
        (c == '.' && i + 1 < s.size() && std::isdigit(static_cast<unsigned char>(s[i + 1])))) {
      std::size_t j = i;
      bool hex = s.compare(i, 2, "0x") == 0 || s.compare(i, 2, "0X") == 0;
      if (hex) {
        j += 2;
        while (j < s.size() && std::isxdigit(static_cast<unsigned char>(s[j]))) ++j;
        if (j == i + 2) throw ExprError("a hex number needs digits", i);
        t.t = Tok::T::num;
        try {
          t.num = std::stoull(s.substr(i + 2, j - i - 2), nullptr, 16);
        } catch (const std::exception &) {
          throw ExprError("number too large", i);
        }
      } else {
        while (j < s.size() && std::isdigit(static_cast<unsigned char>(s[j]))) ++j;
        bool is_float = false;
        if (j < s.size() && s[j] == '.') {
          is_float = true;
          ++j;
          while (j < s.size() && std::isdigit(static_cast<unsigned char>(s[j]))) ++j;
        }
        if (j < s.size() && (s[j] == 'e' || s[j] == 'E')) {
          std::size_t k = j + 1;
          if (k < s.size() && (s[k] == '+' || s[k] == '-')) ++k;
          if (k < s.size() && std::isdigit(static_cast<unsigned char>(s[k]))) {
            is_float = true;
            j = k;
            while (j < s.size() && std::isdigit(static_cast<unsigned char>(s[j]))) ++j;
          }
        }
        if (is_float) {
          t.t = Tok::T::flt;
          t.flt = std::strtod(s.substr(i, j - i).c_str(), nullptr);
          if (j < s.size() && (s[j] == 'f' || s[j] == 'F')) ++j;
        } else {
          t.t = Tok::T::num;
          try {
            t.num = std::stoull(s.substr(i, j - i), nullptr, 10);
          } catch (const std::exception &) {
            throw ExprError("number too large", i);
          }
        }
      }
      if (t.t == Tok::T::num)
        while (j < s.size() && (s[j] == 'u' || s[j] == 'U' || s[j] == 'l' || s[j] == 'L')) {
          if (s[j] == 'u' || s[j] == 'U') t.uns = true;
          else t.lng = true;
          ++j;
        }
      if (j < s.size() && ident_char(s[j])) throw ExprError("not a number: " + s.substr(i, j + 1 - i), i);
      i = j;
      out.push_back(t);
      continue;
    }
    if (c == '\'') {
      // 'A', '\n', '\x41', '\0'
      std::size_t j = i + 1;
      if (j >= s.size()) throw ExprError("unterminated character", i);
      std::uint64_t v = 0;
      if (s[j] == '\\') {
        ++j;
        if (j >= s.size()) throw ExprError("unterminated character", i);
        const char e = s[j++];
        switch (e) {
          case 'n': v = '\n'; break;
          case 't': v = '\t'; break;
          case 'r': v = '\r'; break;
          case '0': v = 0; break;
          case '\\': v = '\\'; break;
          case '\'': v = '\''; break;
          case 'x': {
            std::size_t k = j;
            while (k < s.size() && std::isxdigit(static_cast<unsigned char>(s[k])) && k < j + 2) ++k;
            if (k == j) throw ExprError("\\x needs hex digits", i);
            v = std::stoull(s.substr(j, k - j), nullptr, 16);
            j = k;
            break;
          }
          default: v = static_cast<unsigned char>(e);
        }
      } else {
        v = static_cast<unsigned char>(s[j++]);
      }
      if (j >= s.size() || s[j] != '\'') throw ExprError("unterminated character", i);
      t.t = Tok::T::chr;
      t.num = v;
      i = j + 1;
      out.push_back(t);
      continue;
    }
    if (c == '$' || std::isalpha(static_cast<unsigned char>(c)) || c == '_') {
      std::size_t j = c == '$' ? i + 1 : i;
      const std::size_t start = j;
      while (j < s.size()) {
        if (ident_char(s[j])) ++j;
        else if (s.compare(j, 2, "::") == 0 && j + 2 < s.size() && (ident_char(s[j + 2]) || s[j + 2] == '~')) j += 2;
        else break;
      }
      if (j == start) throw ExprError("$ needs a register name", i);
      t.t = c == '$' ? Tok::T::reg : Tok::T::ident;
      t.s = s.substr(start, j - start);
      i = j;
      out.push_back(t);
      continue;
    }
    static const char *ops[] = {"->", "<<", ">>", "<=", ">=", "==", "!=", "&&", "||"};
    bool two = false;
    for (const char *o : ops)
      if (s.compare(i, 2, o) == 0) {
        t.t = Tok::T::op;
        t.s = o;
        i += 2;
        two = true;
        break;
      }
    if (!two) {
      if (std::strchr("+-*/%&|^~!<>()[].?:", c) == nullptr)
        throw ExprError(std::string("unexpected '") + c + "'", i);
      t.t = Tok::T::op;
      t.s = std::string(1, c);
      ++i;
    }
    out.push_back(t);
  }
  Tok end;
  end.at = s.size();
  out.push_back(end);
  return out;
}

const std::set<std::string> &type_words() {
  static const std::set<std::string> w = {"unsigned", "signed", "short", "long",  "int",  "char",   "float", "double",
                                          "void",     "_Bool",  "bool",  "const", "volatile", "struct", "union", "enum"};
  return w;
}

class Parser {
 public:
  Parser(const std::string &text, const std::function<bool(const std::string &)> &is_type)
      : toks_(lex(text)), is_type_(is_type) {}

  NodeP parse() {
    NodeP n = conditional();
    if (peek().t != Tok::T::end) throw ExprError("unexpected '" + text_of(peek()) + "'", peek().at);
    return n;
  }

 private:
  std::vector<Tok> toks_;
  std::size_t i_ = 0;
  const std::function<bool(const std::string &)> &is_type_;

  const Tok &peek(std::size_t k = 0) const { return toks_[std::min(i_ + k, toks_.size() - 1)]; }
  static std::string text_of(const Tok &t) {
    switch (t.t) {
      case Tok::T::end: return "end";
      case Tok::T::num:
      case Tok::T::chr: return std::to_string(t.num);
      case Tok::T::flt: return std::to_string(t.flt);
      case Tok::T::reg: return "$" + t.s;
      default: return t.s;
    }
  }
  bool is_op(const char *o, std::size_t k = 0) const { return peek(k).t == Tok::T::op && peek(k).s == o; }
  void expect(const char *o) {
    if (!is_op(o)) throw ExprError(std::string("expected '") + o + "'", peek().at);
    ++i_;
  }
  static std::shared_ptr<Node> node(Node::Op op, std::size_t at) {
    auto n = std::make_shared<Node>();
    n->op = op;
    n->at = at;
    return n;
  }

  NodeP conditional() {
    NodeP c = binary(1);
    if (!is_op("?")) return c;
    const std::size_t at = peek().at;
    ++i_;
    NodeP a = conditional();
    expect(":");
    NodeP b = conditional();
    auto n = std::make_shared<Node>();
    n->op = Node::Op::cond;
    n->at = at;
    n->a = c;
    n->b = a;
    n->c = b;
    return n;
  }

  static int prec(const std::string &o) {
    if (o == "||") return 1;
    if (o == "&&") return 2;
    if (o == "|") return 3;
    if (o == "^") return 4;
    if (o == "&") return 5;
    if (o == "==" || o == "!=") return 6;
    if (o == "<" || o == "<=" || o == ">" || o == ">=") return 7;
    if (o == "<<" || o == ">>") return 8;
    if (o == "+" || o == "-") return 9;
    if (o == "*" || o == "/" || o == "%") return 10;
    return 0;
  }

  NodeP binary(int min) {
    NodeP left = unary();
    while (peek().t == Tok::T::op) {
      const std::string o = peek().s;
      const int p = prec(o);
      if (p == 0 || p < min) break;
      const std::size_t at = peek().at;
      ++i_;
      NodeP right = binary(p + 1);
      auto n = std::make_shared<Node>();
      n->op = o == "&&" ? Node::Op::and_ : o == "||" ? Node::Op::or_ : Node::Op::binary;
      n->name = o;
      n->at = at;
      n->a = left;
      n->b = right;
      left = n;
    }
    return left;
  }

  // At '(': whether a type name follows, and it closes with ')'.
  bool cast_ahead() const {
    std::size_t k = 1;
    const Tok &first = peek(k);
    if (first.t != Tok::T::ident) return false;
    if (type_words().count(first.s) == 0 && !(is_type_ && is_type_(first.s))) return false;
    // words, then stars, then ')'
    while (peek(k).t == Tok::T::ident) ++k;
    while (is_op("*", k)) ++k;
    return is_op(")", k);
  }

  // Reads "unsigned int **" up to ')'; returns the base name and the stars.
  std::pair<std::string, int> type_name() {
    std::string name;
    while (peek().t == Tok::T::ident) {
      name += (name.empty() ? "" : " ") + peek().s;
      ++i_;
    }
    int stars = 0;
    while (is_op("*")) {
      ++stars;
      ++i_;
    }
    return {name, stars};
  }

  NodeP unary() {
    const Tok &t = peek();
    if (t.t == Tok::T::op && (t.s == "-" || t.s == "+" || t.s == "!" || t.s == "~" || t.s == "*" || t.s == "&")) {
      ++i_;
      auto n = node(Node::Op::unary, t.at);
      n->name = t.s;
      n->a = unary();
      return n;
    }
    if (t.t == Tok::T::ident && t.s == "sizeof") {
      const std::size_t at = t.at;
      ++i_;
      if (is_op("(") && cast_ahead()) {
        ++i_;
        auto [name, stars] = type_name();
        expect(")");
        auto n = node(Node::Op::sizeof_type, at);
        n->name = name;
        n->stars = stars;
        return n;
      }
      auto n = node(Node::Op::sizeof_type, at);
      n->a = unary();
      return n;
    }
    if (is_op("(") && cast_ahead()) {
      const std::size_t at = t.at;
      ++i_;
      auto [name, stars] = type_name();
      expect(")");
      auto n = node(Node::Op::cast, at);
      n->name = name;
      n->stars = stars;
      n->a = unary();
      return n;
    }
    return postfix();
  }

  NodeP postfix() {
    NodeP n = primary();
    for (;;) {
      if (is_op("[")) {
        const std::size_t at = peek().at;
        ++i_;
        auto x = node(Node::Op::index, at);
        x->a = n;
        x->b = conditional();
        expect("]");
        n = x;
      } else if (is_op(".") || is_op("->")) {
        const bool arrow = is_op("->");
        const std::size_t at = peek().at;
        ++i_;
        if (peek().t != Tok::T::ident) throw ExprError("expected a field name", peek().at);
        auto x = node(arrow ? Node::Op::arrow : Node::Op::member, at);
        x->a = n;
        x->name = peek().s;
        ++i_;
        n = x;
      } else {
        return n;
      }
    }
  }

  NodeP primary() {
    const Tok t = peek();
    switch (t.t) {
      case Tok::T::num:
      case Tok::T::chr: {
        ++i_;
        auto n = node(Node::Op::num, t.at);
        n->num = t.num;
        n->num_unsigned = t.uns;
        n->num_long = t.lng || t.num > 0x7fffffffull;
        n->name = t.t == Tok::T::chr ? "char" : "";
        return n;
      }
      case Tok::T::flt: {
        ++i_;
        auto n = node(Node::Op::flt, t.at);
        n->flt = t.flt;
        return n;
      }
      case Tok::T::ident:
      case Tok::T::reg: {
        ++i_;
        auto n = node(t.t == Tok::T::reg ? Node::Op::reg : Node::Op::ident, t.at);
        n->name = t.s;
        return n;
      }
      case Tok::T::op:
        if (t.s == "(") {
          ++i_;
          NodeP n = conditional();
          expect(")");
          return n;
        }
        throw ExprError("unexpected '" + t.s + "'", t.at);
      case Tok::T::end: throw ExprError("expected a value", t.at);
    }
    throw ExprError("expected a value", t.at);
  }
};

// --- Evaluation ---

class Evaluator {
 public:
  explicit Evaluator(Context &ctx) : ctx_(ctx) {}

  Value eval(const Node &n) {
    switch (n.op) {
      case Node::Op::num: {
        // A character literal is an int, as in C.
        return scalar(integer(n.num_long ? 8 : 4, !n.num_unsigned && n.num <= 0x7fffffffffffffffull), n.num);
      }
      case Node::Op::flt: return real(n.flt, 8);
      case Node::Op::ident:
      case Node::Op::reg: {
        std::optional<Value> v;
        if (ctx_.lookup) v = ctx_.lookup(n.name, n.op == Node::Op::reg);
        if (!v) throw ExprError(n.op == Node::Op::reg ? "no register " + n.name : "no variable, register or symbol named " + n.name, n.at);
        load(*v);
        return *v;
      }
      case Node::Op::unary: return unary(n);
      case Node::Op::binary: return binary(n.name, eval(*n.a), eval(*n.b), n.at);
      case Node::Op::and_:
      case Node::Op::or_: {
        const bool left = truth(eval(*n.a), n.a->at);
        if (n.op == Node::Op::and_ && !left) return scalar(integer(4, true), 0);
        if (n.op == Node::Op::or_ && left) return scalar(integer(4, true), 1);
        return scalar(integer(4, true), truth(eval(*n.b), n.b->at) ? 1 : 0);
      }
      case Node::Op::cond: return truth(eval(*n.a), n.a->at) ? eval(*n.b) : eval(*n.c);
      case Node::Op::cast: return cast(cast_type(n), eval(*n.a), n.at);
      case Node::Op::sizeof_type: {
        const std::uint64_t size = n.a ? eval(*n.a).type->size : cast_type(n)->size;
        return scalar(integer(ctx_.pointer_size, false), size);
      }
      case Node::Op::index: {
        Value base = decay(eval(*n.a));
        Value idx = eval(*n.b);
        if (base.type->kind != K::pointer) {
          if (idx.type->kind == K::pointer || (idx.type->kind == K::array)) std::swap(base, idx);
          base = decay(base);
          if (base.type->kind != K::pointer) throw ExprError("subscript of a non-pointer", n.at);
        }
        return deref(binary("+", base, idx, n.at), n.at);
      }
      case Node::Op::member: return member(eval(*n.a), n.name, n.at);
      case Node::Op::arrow: {
        Value p = decay(eval(*n.a));
        if (p.type->kind != K::pointer) throw ExprError("-> on a non-pointer (" + p.type->name + ")", n.at);
        return member(deref(p, n.at), n.name, n.at);
      }
    }
    throw ExprError("cannot evaluate", n.at);
  }

  bool truth(const Value &v, std::size_t at) {
    if (!v.unknown.empty()) throw ExprError(v.unknown, at);
    if (v.type->kind == K::float_) return as_double(v) != 0;
    if (!v.type->scalar() && v.type->kind != K::array) throw ExprError("a " + v.type->name + " is not a condition", at);
    if (v.type->kind == K::array) return true;
    return to_u64(v.bytes, ctx_.big_endian) != 0;
  }

 private:
  Context &ctx_;

  TypeP cast_type(const Node &n) {
    TypeP t = resolve_type_name(n.name, ctx_);
    if (!t) throw ExprError("no type named " + n.name, n.at);
    for (int i = 0; i < n.stars; ++i) t = pointer_to(t, ctx_.pointer_size);
    return t;
  }

  TypeP target_of(const Type &t) {
    if (t.target) return t.target;
    if (!t.target_hash.empty() && ctx_.types)
      if (auto r = ctx_.types->by_hash(t.target_hash)) return r;
    return undefined(1);
  }

  TypeP field_type(const Field &f) {
    if (f.type) return f.type;
    if (!f.type_hash.empty() && ctx_.types)
      if (auto r = ctx_.types->by_hash(f.type_hash)) return r;
    return undefined(1);
  }

  Value scalar(TypeP t, std::uint64_t v) {
    Value out;
    out.bytes = from_u64(v, t->size, ctx_.big_endian);
    out.type = std::move(t);
    return out;
  }

  Value real(double d, std::uint64_t size) {
    Value out;
    out.type = size == 4 ? builtin("float", ctx_.pointer_size) : builtin("double", ctx_.pointer_size);
    std::uint64_t bits = 0;
    if (size == 4) {
      const float f = static_cast<float>(d);
      std::uint32_t b;
      std::memcpy(&b, &f, 4);
      bits = b;
    } else {
      std::memcpy(&bits, &d, 8);
    }
    out.bytes = from_u64(bits, size, ctx_.big_endian);
    return out;
  }

  double as_double(const Value &v) const {
    const std::uint64_t bits = to_u64(v.bytes, ctx_.big_endian);
    if (v.type->size == 4) {
      const std::uint32_t b = static_cast<std::uint32_t>(bits);
      float f;
      std::memcpy(&f, &b, 4);
      return f;
    }
    double d;
    std::memcpy(&d, &bits, 8);
    return d;
  }

  void load(Value &v) {
    if (!v.bytes.empty() || !v.unknown.empty() || !v.address || !v.type) return;
    std::uint64_t size = v.type->size;
    if (v.type->kind == K::function || v.type->kind == K::void_) return;
    if (size > ctx_.max_read) {
      size = ctx_.max_read;
      v.truncated = true;
    }
    if (size == 0) return;
    std::vector<std::uint8_t> buf(static_cast<std::size_t>(size));
    const std::size_t got = ctx_.read ? ctx_.read(*v.address, buf) : 0;
    if (got < buf.size()) {
      v.unknown = "memory at " + hexs(*v.address + got) + (got ? "" : "") + " is not readable";
      return;
    }
    v.bytes = std::move(buf);
  }

  void need(const Value &v, std::size_t at) {
    if (!v.unknown.empty()) throw ExprError(v.unknown, at);
  }

  // Arrays become pointers to their first element; functions, pointers to them.
  Value decay(Value v) {
    if (v.type->kind == K::array && v.address) {
      Value p = scalar(pointer_to(target_of(*v.type), ctx_.pointer_size), *v.address);
      return p;
    }
    if (v.type->kind == K::function && v.address) return scalar(pointer_to(v.type, ctx_.pointer_size), *v.address);
    return v;
  }

  Value deref(const Value &pv, std::size_t at) {
    Value p = decay(pv);
    need(p, at);
    TypeP t;
    if (p.type->kind == K::pointer) {
      t = target_of(*p.type);
      if (t->kind == K::void_) throw ExprError("dereferencing a void *: cast it, *(int *)p", at);
    } else if (p.type->kind == K::int_ || p.type->kind == K::uint_ || p.type->kind == K::undefined) {
      t = undefined(ctx_.pointer_size);
    } else {
      throw ExprError("dereferencing a " + p.type->name, at);
    }
    Value v;
    v.type = t;
    v.address = to_u64(p.bytes, ctx_.big_endian);
    load(v);
    return v;
  }

  Value member(const Value &s, const std::string &name, std::size_t at) {
    if (s.type->kind != K::struct_ && s.type->kind != K::union_)
      throw ExprError("." + name + " of a " + s.type->name + ", not a struct or union", at);
    for (const Field &f : s.type->fields) {
      if (f.name != name) continue;
      TypeP ft = field_type(f);
      Value v;
      v.type = ft;
      if (f.bit_size != 0) {
        need(s, at);
        std::uint64_t raw = 0;
        const std::size_t from = static_cast<std::size_t>(f.offset);
        const std::size_t n = std::min<std::size_t>(8, s.bytes.size() > from ? s.bytes.size() - from : 0);
        raw = to_u64(std::span(s.bytes).subspan(from, n), ctx_.big_endian);
        raw >>= f.bit_offset;
        if (f.bit_size < 64) raw &= (1ull << f.bit_size) - 1;
        if (ft->is_signed() && f.bit_size < 64 && (raw >> (f.bit_size - 1)) & 1) raw |= ~((1ull << f.bit_size) - 1);
        v.bytes = from_u64(raw, ft->size, ctx_.big_endian);
        return v;
      }
      if (s.address) v.address = *s.address + f.offset;
      if (!s.unknown.empty()) {
        v.unknown = s.unknown;
      } else if (s.bytes.size() >= f.offset + ft->size) {
        v.bytes.assign(s.bytes.begin() + static_cast<std::ptrdiff_t>(f.offset),
                       s.bytes.begin() + static_cast<std::ptrdiff_t>(f.offset + ft->size));
      } else {
        load(v);
      }
      if (!s.reg.empty()) v.reg = s.reg;
      return v;
    }
    throw ExprError(s.type->name + " has no field " + name, at);
  }

  struct Num {
    bool is_float = false;
    double f = 0;
    std::uint64_t u = 0;
    bool is_signed = false;
    std::uint64_t size = 4;
  };
  Num num(const Value &v, std::size_t at) {
    need(v, at);
    if (!v.type->scalar()) throw ExprError("a " + v.type->name + " is not a number", at);
    Num n;
    n.size = std::max<std::uint64_t>(v.type->size, 1);
    if (v.type->kind == K::float_) {
      n.is_float = true;
      n.f = as_double(v);
      return n;
    }
    n.u = to_u64(v.bytes, ctx_.big_endian);
    n.is_signed = v.type->is_signed();
    if (n.is_signed) n.u = static_cast<std::uint64_t>(sign_extend(n.u, n.size));
    return n;
  }

  Value cast(TypeP t, Value v, std::size_t at) {
    v = decay(v);
    if (!t->scalar()) {
      // A reinterpretation of what is at the value's address.
      if (!v.address) throw ExprError("cannot cast a value with no address to " + t->name, at);
      Value out;
      out.type = t;
      out.address = v.address;
      load(out);
      return out;
    }
    Num n = num(v, at);
    if (t->kind == K::float_) return real(n.is_float ? n.f : n.is_signed ? static_cast<double>(static_cast<std::int64_t>(n.u)) : static_cast<double>(n.u), t->size);
    std::uint64_t u = n.is_float ? (n.f < 0 ? static_cast<std::uint64_t>(static_cast<std::int64_t>(n.f)) : static_cast<std::uint64_t>(n.f)) : n.u;
    if (t->kind == K::bool_) u = u != 0;
    Value out = scalar(t, u);
    return out;
  }

  Value unary(const Node &n) {
    const std::string &o = n.name;
    if (o == "&") {
      Value v = eval(*n.a);
      if (!v.address) throw ExprError(v.reg.empty() ? "& of a value with no address" : "& of a register (" + v.reg + ")", n.at);
      return scalar(pointer_to(v.type, ctx_.pointer_size), *v.address);
    }
    if (o == "*") return deref(eval(*n.a), n.at);
    Value v = decay(eval(*n.a));
    Num x = num(v, n.a->at);
    if (o == "+") return v;
    if (o == "!") return scalar(integer(4, true), x.is_float ? x.f == 0 : x.u == 0);
    const TypeP t = promote(v.type);
    if (o == "-") {
      if (x.is_float) return real(-x.f, v.type->size);
      return scalar(t, static_cast<std::uint64_t>(-static_cast<std::int64_t>(x.u)));
    }
    if (o == "~") {
      if (x.is_float) throw ExprError("~ of a floating value", n.at);
      return scalar(t, ~x.u);
    }
    throw ExprError("unknown operator " + o, n.at);
  }

  TypeP promote(const TypeP &t) {
    if (t->kind == K::pointer) return integer(t->size, false);
    if (t->size < 4) return integer(4, true);
    return integer(t->size, t->is_signed());
  }

  Value binary(const std::string &o, Value a, Value b, std::size_t at) {
    a = decay(a);
    b = decay(b);
    const bool pa = a.type->kind == K::pointer, pb = b.type->kind == K::pointer;
    // Pointer arithmetic, scaled by the target's size.
    if ((o == "+" || o == "-") && (pa || pb) && !(pa && pb)) {
      if (pb && o == "-") throw ExprError("integer minus pointer", at);
      const Value &p = pa ? a : b;
      const Num i = num(pa ? b : a, at);
      if (i.is_float) throw ExprError("pointer plus a floating value", at);
      const TypeP target = target_of(*p.type);
      const std::uint64_t scale = target->kind == K::void_ || target->size == 0 ? 1 : target->size;
      const std::uint64_t base = to_u64(p.bytes, ctx_.big_endian);
      need(p, at);
      const std::uint64_t off = i.u * scale;
      return scalar(p.type, o == "+" ? base + off : base - off);
    }
    if (o == "-" && pa && pb) {
      need(a, at);
      need(b, at);
      const TypeP target = target_of(*a.type);
      const std::uint64_t scale = target->kind == K::void_ || target->size == 0 ? 1 : target->size;
      const std::int64_t d = static_cast<std::int64_t>(to_u64(a.bytes, ctx_.big_endian) - to_u64(b.bytes, ctx_.big_endian));
      return scalar(integer(ctx_.pointer_size, true), static_cast<std::uint64_t>(d / static_cast<std::int64_t>(scale)));
    }
    const Num x = num(a, at), y = num(b, at);
    const bool cmp = o == "==" || o == "!=" || o == "<" || o == "<=" || o == ">" || o == ">=";
    if (x.is_float || y.is_float) {
      auto d = [](const Num &n) { return n.is_float ? n.f : n.is_signed ? static_cast<double>(static_cast<std::int64_t>(n.u)) : static_cast<double>(n.u); };
      const double l = d(x), r = d(y);
      auto boolean = [&](bool v) { return scalar(integer(4, true), v ? 1 : 0); };
      if (o == "==") return boolean(l == r);
      if (o == "!=") return boolean(l != r);
      if (o == "<") return boolean(l < r);
      if (o == "<=") return boolean(l <= r);
      if (o == ">") return boolean(l > r);
      if (o == ">=") return boolean(l >= r);
      const std::uint64_t size = std::max(x.is_float ? x.size : 0, y.is_float ? y.size : 0);
      if (o == "+") return real(l + r, size);
      if (o == "-") return real(l - r, size);
      if (o == "*") return real(l * r, size);
      if (o == "/") return real(l / r, size);
      throw ExprError(o + " of a floating value", at);
    }
    // The usual arithmetic conversions, roughly: at least int; unsigned
    // when an unsigned operand is as wide as the result.
    const std::uint64_t size = std::max<std::uint64_t>({4, x.size, y.size});
    const bool uns = (!x.is_signed && x.size >= size) || (!y.is_signed && y.size >= size);
    const TypeP t = integer(std::min<std::uint64_t>(size, 8), !uns);
    auto boolean = [&](bool v) { return scalar(integer(4, true), v ? 1 : 0); };
    const std::int64_t sx = static_cast<std::int64_t>(x.u), sy = static_cast<std::int64_t>(y.u);
    auto mask = [&](std::uint64_t v) { return t->size >= 8 ? v : v & ((1ull << (t->size * 8)) - 1); };
    if (cmp) {
      const std::uint64_t ux = mask(x.u), uy = mask(y.u);
      if (o == "==") return boolean(ux == uy);
      if (o == "!=") return boolean(ux != uy);
      if (uns) {
        if (o == "<") return boolean(ux < uy);
        if (o == "<=") return boolean(ux <= uy);
        if (o == ">") return boolean(ux > uy);
        return boolean(ux >= uy);
      }
      if (o == "<") return boolean(sx < sy);
      if (o == "<=") return boolean(sx <= sy);
      if (o == ">") return boolean(sx > sy);
      return boolean(sx >= sy);
    }
    if (o == "+") return scalar(t, x.u + y.u);
    if (o == "-") return scalar(t, x.u - y.u);
    if (o == "*") return scalar(t, x.u * y.u);
    if (o == "/" || o == "%") {
      if (y.u == 0 || mask(y.u) == 0) throw ExprError("division by zero", at);
      if (uns) return scalar(t, o == "/" ? mask(x.u) / mask(y.u) : mask(x.u) % mask(y.u));
      if (sy == -1) return scalar(t, o == "/" ? static_cast<std::uint64_t>(-sx) : 0);
      return scalar(t, static_cast<std::uint64_t>(o == "/" ? sx / sy : sx % sy));
    }
    if (o == "&") return scalar(t, x.u & y.u);
    if (o == "|") return scalar(t, x.u | y.u);
    if (o == "^") return scalar(t, x.u ^ y.u);
    if (o == "<<" || o == ">>") {
      const std::uint64_t n = y.u;
      if (n >= 64) return scalar(t, o == ">>" && !uns && sx < 0 ? ~0ull : 0);
      if (o == "<<") return scalar(t, x.u << n);
      return scalar(t, uns ? mask(x.u) >> n : static_cast<std::uint64_t>(sx >> n));
    }
    throw ExprError("unknown operator " + o, at);
  }
};

// --- Formatting ---

std::string quote(const std::vector<std::uint8_t> &bytes, std::size_t max, bool *ended) {
  std::string s = "\"";
  *ended = false;
  for (std::size_t i = 0; i < bytes.size() && i < max; ++i) {
    const unsigned char c = bytes[i];
    if (c == 0) {
      *ended = true;
      break;
    }
    if (c == '"' || c == '\\') s += std::string("\\") + static_cast<char>(c);
    else if (c == '\n') s += "\\n";
    else if (c == '\t') s += "\\t";
    else if (c == '\r') s += "\\r";
    else if (c >= 0x20 && c < 0x7f) s += static_cast<char>(c);
    else {
      char buf[8];
      std::snprintf(buf, sizeof buf, "\\x%02x", c);
      s += buf;
    }
  }
  return s + "\"";
}

std::string char_text(std::uint64_t v, std::int64_t sv) {
  std::string out = std::to_string(sv) + " '";
  const unsigned char c = static_cast<unsigned char>(v);
  if (c == 0) out += "\\0";
  else if (c == '\n') out += "\\n";
  else if (c == '\t') out += "\\t";
  else if (c == '\'' || c == '\\') out += std::string("\\") + static_cast<char>(c);
  else if (c >= 0x20 && c < 0x7f) out += static_cast<char>(c);
  else {
    char buf[8];
    std::snprintf(buf, sizeof buf, "\\x%02x", c);
    out += buf;
  }
  return out + "'";
}

class Formatter {
 public:
  explicit Formatter(Context &ctx) : ctx_(ctx) {}

  std::string text(const Value &v, int depth) {
    if (!v.unknown.empty()) return "??";
    const Type &t = *v.type;
    if (v.bytes.empty() && t.size != 0 && t.kind != K::function && t.kind != K::void_) return "??";
    const bool big = ctx_.big_endian;
    switch (t.kind) {
      case K::void_: return "void";
      case K::function: return v.address ? hexs(*v.address) + sym(*v.address) : "<function>";
      case K::bool_: {
        const std::uint64_t u = to_u64(v.bytes, big);
        return u == 0 ? "false" : u == 1 ? "true" : std::to_string(u);
      }
      case K::char_:
      case K::int_:
      case K::uint_: {
        const std::uint64_t u = to_u64(v.bytes, big);
        const std::int64_t s = sign_extend(u, t.size);
        if (t.size == 1 && (t.kind == K::char_ || t.name.find("char") != std::string::npos))
          return char_text(u, t.kind == K::uint_ ? static_cast<std::int64_t>(u & 0xff) : s);
        if (t.size > 8) return hex_bytes(v.bytes);
        return t.is_signed() ? std::to_string(s) : std::to_string(u);
      }
      case K::enum_: {
        const std::uint64_t u = to_u64(v.bytes, big);
        const std::int64_t s = sign_extend(u, t.size);
        for (const auto &[value, name] : t.enumerators)
          if (value == s || static_cast<std::uint64_t>(value) == u) return name;
        return std::to_string(s);
      }
      case K::float_: {
        if (t.size != 4 && t.size != 8) return hex_bytes(v.bytes);
        const std::uint64_t bits = to_u64(v.bytes, big);
        double d;
        if (t.size == 4) {
          const std::uint32_t b = static_cast<std::uint32_t>(bits);
          float f;
          std::memcpy(&f, &b, 4);
          d = f;
        } else {
          std::memcpy(&d, &bits, 8);
        }
        char buf[64];
        std::snprintf(buf, sizeof buf, t.size == 4 ? "%.9g" : "%.17g", d);
        return buf;
      }
      case K::pointer: {
        const std::uint64_t p = to_u64(v.bytes, big);
        std::string out = hexs(p);
        if (p == 0) return out;
        out += sym(p);
        TypeP target = target_of(t);
        if (target->size == 1 && (target->kind == K::char_ || target->name.find("char") != std::string::npos)) {
          std::vector<std::uint8_t> buf(64);
          const std::size_t got = ctx_.read ? ctx_.read(p, buf) : 0;
          buf.resize(got);
          if (got) {
            bool ended = false;
            out += " " + quote(buf, 64, &ended);
            if (!ended) out += "...";
          }
        }
        return out;
      }
      case K::array: {
        TypeP elem = target_of(t);
        if (elem->size == 1 && (elem->kind == K::char_ || elem->name.find("char") != std::string::npos)) {
          bool ended = false;
          std::string s = quote(v.bytes, std::min<std::size_t>(v.bytes.size(), 256), &ended);
          if (!ended && (v.bytes.size() > 256 || v.truncated)) s += "...";
          return s;
        }
        if (depth <= 0) return "{...}";
        std::string out = "{";
        const std::uint64_t n = elem->size ? std::min<std::uint64_t>(t.count, v.bytes.size() / elem->size) : 0;
        for (std::uint64_t i = 0; i < n && i < 16; ++i) {
          if (i) out += ", ";
          out += text(slice(v, elem, i * elem->size), depth - 1);
        }
        if (n > 16 || t.count > n) out += ", ...";
        return out + "}";
      }
      case K::struct_:
      case K::union_: {
        if (depth <= 0) return "{...}";
        std::string out = "{";
        std::size_t shown = 0;
        for (const Field &f : t.fields) {
          if (shown == 16) {
            out += ", ...";
            break;
          }
          if (shown++) out += ", ";
          out += f.name + " = " + text(field(v, f), depth - 1);
        }
        return out + "}";
      }
      case K::undefined: {
        if (t.size > 8) return hex_bytes(v.bytes);
        const std::uint64_t u = to_u64(v.bytes, big);
        return hexs(u);
      }
    }
    return "??";
  }

  std::string hex(const Value &v) {
    if (!v.unknown.empty() || v.bytes.empty() || !v.type->scalar() || v.type->size > 8) return "";
    return hexs(to_u64(v.bytes, ctx_.big_endian));
  }

  std::vector<Formatted::Child> children(const Value &v, int depth) {
    std::vector<Formatted::Child> out;
    if (!v.unknown.empty()) return out;
    const Type &t = *v.type;
    if (t.kind == K::struct_ || t.kind == K::union_) {
      for (const Field &f : t.fields) {
        if (out.size() == 64) break;
        Value fv = field(v, f);
        out.push_back({f.name, text(fv, depth - 1), fv.type->name, fv.address});
      }
    } else if (t.kind == K::array) {
      TypeP elem = target_of(t);
      if (elem->size == 0) return out;
      const std::uint64_t n = std::min<std::uint64_t>(t.count, v.bytes.size() / elem->size);
      for (std::uint64_t i = 0; i < n && i < 64; ++i) {
        Value e = slice(v, elem, i * elem->size);
        out.push_back({"[" + std::to_string(i) + "]", text(e, depth - 1), elem->name, e.address});
      }
    }
    return out;
  }

 private:
  Context &ctx_;

  std::string sym(std::uint64_t a) {
    if (!ctx_.symbolize) return "";
    std::string s = ctx_.symbolize(a);
    return s.empty() ? "" : " <" + s + ">";
  }
  static std::string hex_bytes(const std::vector<std::uint8_t> &b) {
    std::string s;
    char buf[4];
    for (std::uint8_t x : b) {
      std::snprintf(buf, sizeof buf, "%02x", x);
      s += buf;
    }
    return s.empty() ? "??" : s;
  }
  TypeP target_of(const Type &t) {
    if (t.target) return t.target;
    if (!t.target_hash.empty() && ctx_.types)
      if (auto r = ctx_.types->by_hash(t.target_hash)) return r;
    return undefined(1);
  }
  Value slice(const Value &v, const TypeP &type, std::uint64_t offset) {
    Value out;
    out.type = type;
    if (v.address) out.address = *v.address + offset;
    if (v.bytes.size() >= offset + type->size)
      out.bytes.assign(v.bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                       v.bytes.begin() + static_cast<std::ptrdiff_t>(offset + type->size));
    else
      out.unknown = "not read";
    return out;
  }
  Value field(const Value &v, const Field &f) {
    TypeP ft = f.type;
    if (!ft && !f.type_hash.empty() && ctx_.types) ft = ctx_.types->by_hash(f.type_hash);
    if (!ft) ft = undefined(1);
    if (f.bit_size == 0) return slice(v, ft, f.offset);
    Value out;
    out.type = ft;
    const std::size_t from = static_cast<std::size_t>(f.offset);
    if (v.bytes.size() <= from) {
      out.unknown = "not read";
      return out;
    }
    std::uint64_t raw = to_u64(std::span(v.bytes).subspan(from, std::min<std::size_t>(8, v.bytes.size() - from)), ctx_.big_endian);
    raw >>= f.bit_offset;
    if (f.bit_size < 64) raw &= (1ull << f.bit_size) - 1;
    out.bytes = from_u64(raw, ft->size, ctx_.big_endian);
    return out;
  }
};

}  // namespace

Expression Expression::parse(const std::string &text, const std::function<bool(const std::string &)> &is_type) {
  Expression e;
  e.text_ = text;
  Parser p(text, is_type);
  e.root_ = p.parse();
  return e;
}

Value Expression::evaluate(Context &ctx) const {
  if (!root_) throw ExprError("empty expression");
  Evaluator ev(ctx);
  return ev.eval(*root_);
}

bool truthy(const Value &v, bool big_endian) {
  if (!v.unknown.empty()) throw ExprError(v.unknown);
  if (!v.type) return false;
  if (v.type->kind == K::array) return true;
  if (!v.type->scalar()) throw ExprError("a " + v.type->name + " is not a condition");
  if (v.type->kind == K::float_) {
    const std::uint64_t bits = to_u64(v.bytes, big_endian);
    if (v.type->size == 4) {
      const std::uint32_t b = static_cast<std::uint32_t>(bits);
      float f;
      std::memcpy(&f, &b, 4);
      return f != 0;
    }
    double d;
    std::memcpy(&d, &bits, 8);
    return d != 0;
  }
  return to_u64(v.bytes, big_endian) != 0;
}

Formatted format(const Value &v, Context &ctx, int depth) {
  Formatter f(ctx);
  Formatted out;
  if (!v.type) {
    out.text = "??";
    return out;
  }
  out.text = f.text(v, depth);
  out.hex = f.hex(v);
  out.children = f.children(v, depth);
  return out;
}

}  // namespace revkit::debug::expr
