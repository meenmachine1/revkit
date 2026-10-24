// BER/DER (X.690), CMS SignedData (RFC 5652) and X.509 names (RFC 5280),
// read from their public specifications for hostile input; and Apple's
// DER entitlements encoding (a property list as DER: dictionaries of
// key/value sequences, arrays as sequences), as Apple's open-source
// Security and libCoreEntitlements describe it.

#include "der.hh"

#include "text.hh"

#include <cstring>

namespace revkit::apple::detail {

namespace {

constexpr unsigned kMaxDepth = 64;
constexpr std::size_t kMaxChildren = 1 << 16;

std::uint8_t at8(std::span<const std::byte> b, std::size_t i) {
  if (i >= b.size()) throw Error("DER data truncated");
  return static_cast<std::uint8_t>(b[i]);
}

}  // namespace

Tlv read_tlv(std::span<const std::byte> b, std::size_t at, unsigned depth) {
  if (depth > kMaxDepth) throw LimitError("DER data nests too deep");
  Tlv t;
  const std::size_t start = at;
  const std::uint8_t id = at8(b, at++);
  t.first = id;
  t.cls = id >> 6;
  t.constructed = (id & 0x20) != 0;
  t.tag = id & 0x1f;
  if (t.tag == 0x1f) {
    t.tag = 0;
    for (int n = 0;; ++n) {
      if (n >= 4) throw Error("a DER tag number too large");
      const std::uint8_t c = at8(b, at++);
      t.tag = t.tag << 7 | (c & 0x7f);
      if (!(c & 0x80)) break;
    }
  }
  const std::uint8_t l = at8(b, at++);
  if (l == 0x80) {
    // Indefinite: the content runs to the end-of-contents marker.
    if (!t.constructed) throw Error("an indefinite length on a primitive DER element");
    std::size_t p = at;
    for (std::size_t n = 0;; ++n) {
      if (n > kMaxChildren) throw LimitError("too many DER elements");
      if (at8(b, p) == 0 && at8(b, p + 1) == 0) break;
      p += read_tlv(b, p, depth + 1).total;
    }
    t.content = b.subspan(at, p - at);
    t.total = p + 2 - start;
    return t;
  }
  std::uint64_t len = l;
  if (l & 0x80) {
    const unsigned n = l & 0x7f;
    if (n > 8) throw Error("a DER length too large");
    len = 0;
    for (unsigned i = 0; i < n; ++i) len = len << 8 | at8(b, at++);
  }
  if (at > b.size() || len > b.size() - at) throw Error("a DER element runs past its data");
  t.content = b.subspan(at, static_cast<std::size_t>(len));
  t.total = at + static_cast<std::size_t>(len) - start;
  return t;
}

std::vector<Tlv> children(const Tlv &t, unsigned depth) {
  std::vector<Tlv> out;
  if (!t.constructed) return out;
  for (std::size_t p = 0; p < t.content.size();) {
    if (out.size() >= kMaxChildren) throw LimitError("too many DER elements");
    Tlv c = read_tlv(t.content, p, depth + 1);
    p += c.total;
    out.push_back(c);
  }
  return out;
}

std::string octets(const Tlv &t, unsigned depth) {
  if (depth > kMaxDepth) throw LimitError("DER data nests too deep");
  if (!t.constructed) return std::string(reinterpret_cast<const char *>(t.content.data()), t.content.size());
  std::string out;
  for (const Tlv &c : children(t, depth)) out += octets(c, depth + 1);
  return out;
}

std::string oid_text(std::span<const std::byte> c) {
  std::string out;
  std::uint64_t v = 0;
  bool first = true;
  for (std::size_t i = 0; i < c.size(); ++i) {
    const auto b = static_cast<std::uint8_t>(c[i]);
    if (v > (UINT64_MAX >> 7)) return out + "?";
    v = v << 7 | (b & 0x7f);
    if (b & 0x80) continue;
    if (first) {
      const std::uint64_t a = v < 80 ? v / 40 : 2;
      out = std::to_string(a) + "." + std::to_string(v - a * 40);
      first = false;
    } else {
      out += "." + std::to_string(v);
    }
    v = 0;
  }
  return out;
}

namespace {

// A directory string (UTF8String, PrintableString, IA5String, T61String,
// BMPString) as UTF-8.
std::string name_string(const Tlv &t) {
  const std::string raw = octets(t);
  if (t.cls == 0 && t.tag == 30) {  // BMPString: UTF-16BE
    std::vector<std::uint16_t> u;
    for (std::size_t i = 0; i + 1 < raw.size(); i += 2)
      u.push_back(static_cast<std::uint16_t>(static_cast<std::uint8_t>(raw[i]) << 8 | static_cast<std::uint8_t>(raw[i + 1])));
    return utf16_to_utf8(u);
  }
  return valid_utf8(raw);
}

struct Name {
  std::string text, cn, ou, o;
};

Name read_name(const Tlv &name) {
  static const std::pair<const char *, const char *> kNames[] = {
      {"2.5.4.3", "CN"}, {"2.5.4.11", "OU"}, {"2.5.4.10", "O"}, {"2.5.4.6", "C"},
      {"2.5.4.7", "L"},  {"2.5.4.8", "ST"},  {"0.9.2342.19200300.100.1.1", "UID"}};
  Name out;
  for (const Tlv &rdn : children(name))
    for (const Tlv &atv : children(rdn)) {
      const auto parts = children(atv);
      if (parts.size() < 2 || parts[0].tag != 6) continue;
      const std::string oid = oid_text(parts[0].content);
      const std::string value = name_string(parts[1]);
      std::string label = oid;
      for (const auto &[o, l] : kNames)
        if (oid == o) label = l;
      if (!out.text.empty()) out.text += ", ";
      out.text += label + "=" + value;
      if (label == "CN") out.cn = value;
      else if (label == "OU") out.ou = value;
      else if (label == "O") out.o = value;
    }
  return out;
}

Certificate read_certificate(const Tlv &cert) {
  Certificate c;
  const auto top = children(cert);
  if (top.empty()) return c;
  auto tbs = children(top[0]);
  std::size_t i = 0;
  if (i < tbs.size() && tbs[i].cls == 2 && tbs[i].tag == 0) ++i;  // [0] version
  i += 2;                                                          // serial, signature algorithm
  if (i < tbs.size()) c.issuer = read_name(tbs[i]).cn;
  ++i;
  if (i < tbs.size()) {
    const auto validity = children(tbs[i]);
    if (validity.size() >= 2) {
      c.not_before = valid_utf8(octets(validity[0]));
      c.not_after = valid_utf8(octets(validity[1]));
    }
  }
  ++i;
  if (i < tbs.size()) {
    Name n = read_name(tbs[i]);
    c.subject = n.text;
    c.common_name = n.cn;
    c.organizational_unit = n.ou;
    c.organization = n.o;
  }
  return c;
}

}  // namespace

SignedData read_signed_data(std::span<const std::byte> der) {
  const Tlv info = read_tlv(der);
  const auto ci = children(info);
  if (ci.size() < 2 || ci[0].tag != 6 || oid_text(ci[0].content) != "1.2.840.113549.1.7.2")
    throw Error("not CMS signed data");
  const auto explicit0 = children(ci[1]);
  if (explicit0.empty()) throw Error("CMS signed data without its content");
  const auto sd = children(explicit0[0]);
  if (sd.size() < 3) throw Error("a malformed CMS SignedData");
  SignedData out;
  // version, digestAlgorithms, encapContentInfo, [0] certificates, [1] crls, signerInfos
  const auto encap = children(sd[2]);
  if (!encap.empty() && encap[0].tag == 6) out.content_type = oid_text(encap[0].content);
  if (encap.size() >= 2 && encap[1].cls == 2 && encap[1].tag == 0) {
    const auto inner = children(encap[1]);
    if (!inner.empty()) out.content = octets(inner[0]);
  }
  for (std::size_t i = 3; i < sd.size(); ++i) {
    if (sd[i].cls == 2 && sd[i].tag == 0) {
      for (const Tlv &cert : children(sd[i]))
        if (out.certificates.size() < 64) out.certificates.push_back(read_certificate(cert));
    } else if (sd[i].cls == 0 && sd[i].tag == 17) {
      out.signers = children(sd[i]).size();
    }
  }
  return out;
}

namespace {

Value der_value(const Tlv &t, unsigned depth, std::uint64_t &count) {
  if (depth > kMaxDepth) throw LimitError("DER entitlements nest too deep");
  if (++count > (1u << 20)) throw LimitError("too many DER entitlement values");
  Value v;
  if (t.cls == 0 && !t.constructed) {
    switch (t.tag) {
      case 1:
        v.type = Value::Type::boolean;
        v.boolean = !t.content.empty() && t.content[0] != std::byte{0};
        return v;
      case 2: {
        v.type = Value::Type::integer;
        if (t.content.empty() || t.content.size() > 9) throw Error("a DER integer of bad size");
        std::int64_t x = static_cast<std::int8_t>(t.content[0]);
        for (std::size_t i = 1; i < t.content.size(); ++i) x = static_cast<std::int64_t>(static_cast<std::uint64_t>(x) << 8) | static_cast<std::uint8_t>(t.content[i]);
        if (t.content.size() == 9 && t.content[0] == std::byte{0}) {
          v.big = true;
          v.unsigned_value = static_cast<std::uint64_t>(x);
        } else {
          v.integer = x;
        }
        return v;
      }
      case 4:
        v.type = Value::Type::data;
        v.bytes = octets(t);
        return v;
      case 12:
      case 19:
      case 22:
        v.type = Value::Type::string;
        v.bytes = valid_utf8(octets(t));
        return v;
      case 24: {
        // GeneralizedTime "YYYYMMDDHHMMSSZ".
        const std::string s = octets(t);
        if (s.size() >= 15) {
          const std::string iso = s.substr(0, 4) + "-" + s.substr(4, 2) + "-" + s.substr(6, 2) + "T" + s.substr(8, 2) +
                                  ":" + s.substr(10, 2) + ":" + s.substr(12, 2) + "Z";
          if (auto d = parse_iso8601(iso)) {
            v.type = Value::Type::date;
            v.real = *d;
            return v;
          }
        }
        v.type = Value::Type::string;
        v.bytes = valid_utf8(s);
        return v;
      }
      case 5:
        return v;  // NULL
      default:
        break;
    }
  }
  // [CONTEXT 16] (and a SET): a dictionary of {key, value} sequences.
  if (t.constructed && ((t.cls == 2 && t.tag == 16) || (t.cls == 0 && t.tag == 17))) {
    v.type = Value::Type::dict;
    for (const Tlv &e : children(t, depth)) {
      const auto kv = children(e, depth);
      if (kv.size() != 2 || !(kv[0].cls == 0 && kv[0].tag == 12)) throw Error("a DER entitlements dictionary entry that isn't a key and a value");
      v.dict.push_back(DictEntry{valid_utf8(octets(kv[0])), der_value(kv[1], depth + 1, count)});
    }
    dedupe(v.dict);
    return v;
  }
  if (t.constructed && t.cls == 0 && t.tag == 16) {
    v.type = Value::Type::array;
    for (const Tlv &e : children(t, depth)) v.array.push_back(der_value(e, depth + 1, count));
    return v;
  }
  throw Error("an unknown DER entitlements element (class " + std::to_string(t.cls) + ", tag " + std::to_string(t.tag) + ")");
}

}  // namespace

Value der_plist(std::span<const std::byte> der) {
  const Tlv top = read_tlv(der);
  std::uint64_t count = 0;
  // [APPLICATION 16] { INTEGER version, dictionary }
  if (top.cls == 1 && top.tag == 16) {
    const auto parts = children(top);
    if (parts.size() != 2 || parts[0].tag != 2) throw Error("malformed DER entitlements");
    return der_value(parts[1], 1, count);
  }
  return der_value(top, 1, count);
}

}  // namespace revkit::apple::detail
