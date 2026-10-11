#include "revkit/analysis/user_refs.h"

#include <charconv>
#include <cstdio>
#include <cstring>

namespace revkit::analysis {

namespace {

std::uint64_t mask_of(unsigned bits) { return bits == 0 || bits >= 64 ? ~std::uint64_t{0} : (std::uint64_t{1} << bits) - 1; }

std::string hex(std::uint64_t v) {
  char buf[24];
  std::snprintf(buf, sizeof buf, "%llx", static_cast<unsigned long long>(v));
  return buf;
}

std::optional<std::uint64_t> parse_hex(std::string_view s) {
  if (s.empty() || s.size() > 16) return std::nullopt;
  std::uint64_t v = 0;
  auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v, 16);
  if (ec != std::errc() || p != s.data() + s.size()) return std::nullopt;
  return v;
}

// Whether `v` is its low `bits` zero- or sign-extended.
bool extends(std::uint64_t v, unsigned bits) {
  const std::uint64_t m = mask_of(bits);
  const std::uint64_t high = v & ~m;
  if (high == 0) return true;
  const bool negative = (v >> (bits - 1)) & 1;
  return negative && high == ~m;
}

}  // namespace

std::string encode_operand_display(const OperandDisplay &d) {
  if (!d.enum_type.empty()) return "m:" + d.enum_type + ":" + d.member;
  if (!d.name.empty()) return "e:" + d.name;
  if (d.format == ScalarFormat::none) return {};
  return "f:" + std::to_string(static_cast<int>(d.format));
}

std::optional<OperandDisplay> parse_operand_display(std::string_view text) {
  OperandDisplay d;
  if (text.empty()) return d;
  if (text.size() < 3 || text[1] != ':') return std::nullopt;
  const std::string_view rest = text.substr(2);
  switch (text[0]) {
    case 'f': {
      int n = 0;
      auto [p, ec] = std::from_chars(rest.data(), rest.data() + rest.size(), n);
      if (ec != std::errc() || p != rest.data() + rest.size() || n < 1 || n > 7) return std::nullopt;
      d.format = static_cast<ScalarFormat>(n);
      return d;
    }
    case 'e':
      d.name = std::string(rest);
      return d;
    case 'm': {
      const auto colon = rest.find(':');
      if (colon == std::string_view::npos || colon == 0 || colon + 1 == rest.size()) return std::nullopt;
      d.enum_type = std::string(rest.substr(0, colon));
      d.member = std::string(rest.substr(colon + 1));
      d.name = d.member;
      return d;
    }
    default: return std::nullopt;
  }
}

std::string equate_sub(int operand, std::uint64_t hash, std::uint64_t value) {
  if (operand < 0) return "h" + hex(hash) + ":" + hex(value);
  return std::to_string(operand) + ":" + hex(value);
}

std::optional<EquateSub> parse_equate_sub(std::string_view sub) {
  const auto colon = sub.find(':');
  if (colon == std::string_view::npos || colon == 0) return std::nullopt;
  EquateSub s;
  const std::string_view head = sub.substr(0, colon);
  auto value = parse_hex(sub.substr(colon + 1));
  if (!value) return std::nullopt;
  s.value = *value;
  if (head[0] == 'h') {
    auto h = parse_hex(head.substr(1));
    if (!h) return std::nullopt;
    s.hash = *h;
    return s;
  }
  int op = 0;
  auto [p, ec] = std::from_chars(head.data(), head.data() + head.size(), op);
  if (ec != std::errc() || p != head.data() + head.size() || op < 0 || op > 255) return std::nullopt;
  s.operand = op;
  return s;
}

bool scalar_matches(std::uint64_t a, std::uint64_t b, unsigned bits) {
  if (a == b) return true;
  if (bits == 0 || bits >= 64) return false;
  const std::uint64_t m = mask_of(bits);
  return (a & m) == (b & m) && extends(a, bits) && extends(b, bits);
}

std::string format_scalar(std::uint64_t value, unsigned bits, ScalarFormat f) {
  if (bits == 0 || bits > 64) bits = 64;
  const std::uint64_t u = value & mask_of(bits);
  char buf[96];
  switch (f) {
    case ScalarFormat::none: return {};
    case ScalarFormat::hex: std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(u)); return buf;
    case ScalarFormat::signed_dec: {
      std::int64_t s = static_cast<std::int64_t>(u);
      if (bits < 64 && ((u >> (bits - 1)) & 1)) s = static_cast<std::int64_t>(u | ~mask_of(bits));
      std::snprintf(buf, sizeof buf, "%lld", static_cast<long long>(s));
      return buf;
    }
    case ScalarFormat::unsigned_dec: std::snprintf(buf, sizeof buf, "%llu", static_cast<unsigned long long>(u)); return buf;
    case ScalarFormat::octal: std::snprintf(buf, sizeof buf, "%llo", static_cast<unsigned long long>(u)); return std::string(buf) + "o";
    case ScalarFormat::binary: {
      std::string out;
      for (int i = static_cast<int>(bits) - 1; i >= 0; --i)
        if (!out.empty() || ((u >> i) & 1)) out += ((u >> i) & 1) ? '1' : '0';
      if (out.empty()) out = "0";
      return out + "b";
    }
    case ScalarFormat::chr: {
      // The value's bytes, most significant first, from its first nonzero
      // one (a single byte at least).
      const unsigned bytes = (bits + 7) / 8;
      int first = 0;
      for (int i = static_cast<int>(bytes) - 1; i > 0; --i)
        if ((u >> (8 * i)) & 0xff) {
          first = i;
          break;
        }
      std::string out = "'";
      for (int i = first; i >= 0; --i) {
        const unsigned c = (u >> (8 * i)) & 0xff;
        switch (c) {
          case 0: out += "\\0"; break;
          case '\a': out += "\\a"; break;
          case '\b': out += "\\b"; break;
          case '\t': out += "\\t"; break;
          case '\n': out += "\\n"; break;
          case '\v': out += "\\v"; break;
          case '\f': out += "\\f"; break;
          case '\r': out += "\\r"; break;
          case '\\': out += "\\\\"; break;
          case '\'': out += "\\'"; break;
          default:
            if (c >= 0x20 && c < 0x7f) {
              out += static_cast<char>(c);
            } else {
              std::snprintf(buf, sizeof buf, "\\x%02x", c);
              out += buf;
            }
        }
      }
      return out + "'";
    }
    case ScalarFormat::flt: {
      std::to_chars_result r;
      if (bits == 32) {
        const auto w = static_cast<std::uint32_t>(u);
        float x;
        std::memcpy(&x, &w, sizeof x);
        r = std::to_chars(buf, buf + sizeof buf, x);
      } else if (bits == 64) {
        double x;
        std::memcpy(&x, &u, sizeof x);
        r = std::to_chars(buf, buf + sizeof buf, x);
      } else {
        return {};
      }
      std::string out(buf, r.ptr);
      // As Java's Float.toString: a whole number keeps ".0".
      if (out.find_first_of(".einfa") == std::string::npos) out += ".0";
      return out;
    }
  }
  return {};
}

std::string user_ref_sub(int operand, std::uint64_t to) { return (operand < 0 ? std::string("i") : std::to_string(operand)) + ":" + hex(to); }

std::string encode_user_ref(const UserRef &r) {
  if (r.remove) return "remove";
  return std::to_string(static_cast<int>(r.type)) + (r.primary ? "p" : "");
}

std::optional<UserRef> parse_user_ref(std::string_view sub, std::string_view value) {
  UserRef r;
  const auto colon = sub.find(':');
  if (colon == std::string_view::npos || colon == 0) return std::nullopt;
  const std::string_view op = sub.substr(0, colon);
  auto to = parse_hex(sub.substr(colon + 1));
  if (!to) return std::nullopt;
  r.to = *to;
  if (op == "i") {
    r.operand = -1;
  } else {
    int n = 0;
    auto [p, ec] = std::from_chars(op.data(), op.data() + op.size(), n);
    if (ec != std::errc() || p != op.data() + op.size() || n < 0 || n > 255) return std::nullopt;
    r.operand = n;
  }
  if (value == "remove") {
    r.remove = true;
    return r;
  }
  if (value.empty() || value[0] < '1' || value[0] > '7') return std::nullopt;
  r.type = static_cast<UserRefType>(value[0] - '0');
  const std::string_view flags = value.substr(1);
  if (flags == "p") r.primary = true;
  else if (!flags.empty()) return std::nullopt;
  return r;
}

}  // namespace revkit::analysis
