#include "revkit/infer/vtype.h"

#include <cctype>

namespace revkit::infer {

namespace {

constexpr int kMaxDepth = 4;

int meta_rank(Meta m) {
  // How much a meta says, for join: anything beats unknown.
  switch (m) {
    case Meta::unknown: return 0;
    default: return 1;
  }
}

}  // namespace

int VType::depth() const {
  int d = 0;
  const VType *t = this;
  while (t->is_pointer()) {
    ++d;
    t = &t->target();
  }
  return d;
}

const VType &VType::innermost() const {
  const VType *t = this;
  while (t->is_pointer()) t = &t->target();
  return *t;
}

bool VType::informative() const {
  if (meta == Meta::unknown) return false;
  if (meta == Meta::int_) return true;
  return true;
}

void VType::encode(facts::Encoder &e) const {
  e.u8(static_cast<std::uint8_t>(meta));
  e.u8(size);
  e.u8(static_cast<std::uint8_t>(sign) | (long_long ? 0x80 : 0));
  if (meta == Meta::struct_ || meta == Meta::code) e.bytes(name);
  if (meta == Meta::pointer || meta == Meta::code) {
    e.varint(pointee.size());
    for (const VType &t : pointee) t.encode(e);
  }
}

VType VType::decode(facts::Decoder &d) {
  VType t;
  std::uint8_t m = d.u8();
  if (m > static_cast<std::uint8_t>(Meta::code)) throw facts::DecodeError("bad type meta");
  t.meta = static_cast<Meta>(m);
  t.size = d.u8();
  std::uint8_t s = d.u8();
  t.long_long = (s & 0x80) != 0;
  if ((s & 0x7f) > static_cast<std::uint8_t>(Sign::is_unsigned)) throw facts::DecodeError("bad sign");
  t.sign = static_cast<Sign>(s & 0x7f);
  if (t.meta == Meta::struct_ || t.meta == Meta::code) t.name = std::string(d.bytes());
  if (t.meta == Meta::pointer || t.meta == Meta::code) {
    const std::size_t n = d.count();
    if (t.meta == Meta::pointer && n > 1) throw facts::DecodeError("pointer with several targets");
    for (std::size_t i = 0; i < n; ++i) t.pointee.push_back(VType::decode(d));
  }
  return t;
}

std::string print(const VType &t, const DataOrg &org) {
  switch (t.meta) {
    case Meta::unknown:
      return t.size <= 1 ? std::string("undefined") : "undefined" + std::to_string(t.size);
    case Meta::void_: return "void";
    case Meta::bool_: return "bool";
    case Meta::char_: return "char";
    case Meta::code: {
      if (t.pointee.empty()) return "code";
      // Ghidra's name for an anonymous function type: _func_ and the
      // return and parameter types, '*' spelled _ptr.
      std::string out = "_func";
      for (const VType &p : t.pointee) {
        std::string s = print(p, org);
        std::string tok;
        for (std::size_t i = 0; i < s.size(); ++i) {
          if (s[i] == ' ') continue;
          if (s[i] == '*') tok += "_ptr";
          else tok += s[i];
        }
        out += "_" + tok;
      }
      if (t.name == "...") out += "_...";
      return out;
    }
    case Meta::struct_: return t.name.empty() ? std::string("struct") : t.name;
    case Meta::float_:
      switch (t.size) {
        case 4: return "float";
        case 8: return "double";
        case 2: return "float2";
        default: return "longdouble";
      }
    case Meta::int_: {
      const bool u = t.sign == Sign::is_unsigned;
      switch (t.size) {
        case 1: return u ? "uchar" : "char";
        case 2: return u ? "ushort" : "short";
        case 4: return u ? "uint" : "int";
        case 8:
          if (org.long_size == 8 && !t.long_long) return u ? "ulong" : "long";
          return u ? "ulonglong" : "longlong";
        case 16: return u ? "uint128" : "int128";
        default: return (u ? "uint" : "int") + std::to_string(t.size);
      }
    }
    case Meta::pointer:
      if (t.pointee.empty()) return "void *";
      return print(t.target(), org) + " *";
  }
  return "undefined";
}

std::optional<VType> parse_type(std::string_view text, const DataOrg &org) {
  // Trim, peel trailing stars.
  auto trim = [](std::string_view s) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.remove_prefix(1);
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.remove_suffix(1);
    return s;
  };
  text = trim(text);
  int stars = 0;
  while (!text.empty() && text.back() == '*') {
    ++stars;
    text.remove_suffix(1);
    text = trim(text);
  }
  if (text.empty()) return std::nullopt;
  const std::string base(text);
  VType t;
  const std::uint8_t L = org.long_size;
  struct Named {
    const char *name;
    Meta meta;
    std::uint8_t size;
    Sign sign;
    bool ll;
  };
  static const Named kNames[] = {
      {"void", Meta::void_, 0, Sign::unknown, false},
      {"bool", Meta::bool_, 1, Sign::unknown, false},
      {"char", Meta::char_, 1, Sign::unknown, false},
      {"schar", Meta::int_, 1, Sign::is_signed, false},
      {"uchar", Meta::int_, 1, Sign::is_unsigned, false},
      {"short", Meta::int_, 2, Sign::is_signed, false},
      {"ushort", Meta::int_, 2, Sign::is_unsigned, false},
      {"int", Meta::int_, 4, Sign::is_signed, false},
      {"uint", Meta::int_, 4, Sign::is_unsigned, false},
      {"longlong", Meta::int_, 8, Sign::is_signed, true},
      {"ulonglong", Meta::int_, 8, Sign::is_unsigned, true},
      {"int128", Meta::int_, 16, Sign::is_signed, false},
      {"uint128", Meta::int_, 16, Sign::is_unsigned, false},
      {"float", Meta::float_, 4, Sign::unknown, false},
      {"double", Meta::float_, 8, Sign::unknown, false},
      {"longdouble", Meta::float_, 16, Sign::unknown, false},
      {"code", Meta::code, 0, Sign::unknown, false},
      {"wchar_t", Meta::int_, 4, Sign::is_signed, false},
  };
  bool found = false;
  for (const Named &n : kNames) {
    if (base == n.name) {
      t = {n.meta, n.size, n.sign, n.ll && L == 8, {}, {}};
      found = true;
      break;
    }
  }
  if (!found) {
    if (base == "long" || base == "ulong") {
      t = VType::integer(L, base == "long" ? Sign::is_signed : Sign::is_unsigned);
    } else if (base.starts_with("undefined")) {
      std::string n = base.substr(9);
      t = VType::unknown(n.empty() ? 1 : static_cast<std::uint8_t>(std::stoi(n)));
    } else {
      t = VType::structure(base);
    }
  }
  for (int i = 0; i < stars; ++i) t = VType::pointer_to(std::move(t), org.pointer_size);
  return t;
}

VType join(const VType &a, const VType &b) {
  if (a == b) return a;
  if (meta_rank(a.meta) == 0 && meta_rank(b.meta) != 0) return b;
  if (meta_rank(b.meta) == 0) return meta_rank(a.meta) == 0 && b.size > a.size ? b : a;
  // Pointers: a pointer beats an integer of its size (pointer arithmetic
  // makes Ghidra call a struct pointer "long"); targets join recursively,
  // with void and unknown targets saying the least.
  if (a.meta == Meta::pointer && b.meta == Meta::pointer) {
    if (a.pointee.empty()) return b;
    if (b.pointee.empty()) return a;
    const VType &ta = a.target(), &tb = b.target();
    if (a.depth() > kMaxDepth) return a;
    auto weak = [](const VType &t) { return t.meta == Meta::unknown || t.meta == Meta::void_; };
    if (weak(ta) && !weak(tb)) return b;
    if (weak(tb)) return a;
    return VType::pointer_to(join(ta, tb), a.size);
  }
  if (a.meta == Meta::code && b.meta == Meta::code) return a.pointee.empty() ? b : a;
  if (a.meta == Meta::pointer && b.meta == Meta::int_ && b.size == a.size) return a;
  if (b.meta == Meta::pointer && a.meta == Meta::int_ && a.size == b.size) return b;
  // Integers: a known signedness beats an unknown one; plain char beats a
  // 1-byte integer; otherwise the first wins.
  if (a.meta == Meta::int_ && b.meta == Meta::int_ && a.size == b.size) {
    if (a.sign == Sign::unknown) return b;
    return a;
  }
  if (a.meta == Meta::char_ && b.meta == Meta::int_ && b.size == 1) return a;
  if (b.meta == Meta::char_ && a.meta == Meta::int_ && a.size == 1) return b;
  return a;
}

VType VType::code_of(const Prototype &p) {
  VType t = code_type();
  t.pointee.push_back(p.ret);
  for (const VType &q : p.params) t.pointee.push_back(q);
  if (p.varargs) t.name = "...";
  return t;
}

VType widen(const VType &t) {
  if (t.meta == Meta::pointer) return VType::pointer_to(VType::unknown(1), t.size);
  return VType::unknown(t.size);
}

std::string Prototype::print(const std::string &name, const DataOrg &org) const {
  std::string out = infer::print(ret, org);
  out += ' ';
  out += name;
  out += '(';
  for (std::size_t i = 0; i < params.size(); ++i) {
    if (i) out += ", ";
    out += infer::print(params[i], org);
    out += " param_" + std::to_string(i + 1);
  }
  if (varargs) out += params.empty() ? "..." : ", ...";
  if (params.empty() && !varargs) out += "void";
  out += ')';
  return out;
}

void Prototype::encode(facts::Encoder &e) const {
  ret.encode(e);
  facts::encode(e, params);
  facts::encode(e, varargs);
  e.bytes(source);
}

Prototype Prototype::decode(facts::Decoder &d) {
  Prototype p;
  p.ret = VType::decode(d);
  p.params = facts::decode<std::vector<VType>>(d);
  p.varargs = facts::decode<bool>(d);
  p.source = std::string(d.bytes());
  return p;
}

}  // namespace revkit::infer
