// Apple's data formats named in listings (docs/apple-apps.md): property
// lists (XML, bplist00), NSKeyedArchiver archives, compiled nibs
// (NIBArchive, and keyed-archive nibs), provisioning profiles (CMS signed
// data around a plist) and code signature SuperBlobs. By their first
// bytes only; revkit::apple reads them.

#include "bytecode.hh"
#include "formats.hh"

#include <algorithm>
#include <cctype>
#include <cstring>

namespace revkit::container::detail {

namespace {

bool contains(std::span<const std::byte> b, std::string_view needle) {
  const std::string_view hay(reinterpret_cast<const char *>(b.data()), b.size());
  return hay.find(needle) != std::string_view::npos;
}

// The head as ASCII text: UTF-16 (with its byte-order mark) narrowed, a
// UTF-8 mark dropped; at most 4 KiB.
std::string ascii_head(std::span<const std::byte> b) {
  auto u = [&](std::size_t i) { return static_cast<std::uint8_t>(b[i]); };
  std::string out;
  const std::size_t n = std::min<std::size_t>(b.size(), 8192);
  if (n >= 2 && ((u(0) == 0xff && u(1) == 0xfe) || (u(0) == 0xfe && u(1) == 0xff))) {
    const bool le = u(0) == 0xff;
    for (std::size_t i = 2; i + 1 < n; i += 2) {
      const unsigned c = le ? (u(i) | u(i + 1) << 8) : (u(i) << 8 | u(i + 1));
      out += c < 0x80 ? static_cast<char>(c) : '?';
    }
    return out;
  }
  std::size_t start = n >= 3 && u(0) == 0xef && u(1) == 0xbb && u(2) == 0xbf ? 3 : 0;
  return std::string(reinterpret_cast<const char *>(b.data() + start), std::min<std::size_t>(n - start, 4096));
}

Guess make(std::string kind, std::string format, std::string description, std::string content_kind) {
  Guess g;
  g.kind = std::move(kind);
  g.format = std::move(format);
  g.description = std::move(description);
  g.content_kind = std::move(content_kind);
  return g;
}

}  // namespace

std::optional<Guess> apple_guess(std::span<const std::byte> b) {
  auto at = [&](std::string_view magic) {
    return b.size() >= magic.size() && std::memcmp(b.data(), magic.data(), magic.size()) == 0;
  };
  if (at("bplist00")) {
    if (contains(b, "NSKeyedArchiver")) {
      if (contains(b, "IB.objectdata"))
        return make("data", "bplist", "compiled nib (NSKeyedArchiver archive)", "nib:keyed");
      return make("data", "bplist", "binary property list (NSKeyedArchiver archive)", "keyed-archive");
    }
    return make("data", "bplist", "binary property list", "plist:binary");
  }
  if (at("NIBArchive") && b.size() >= 22) {
    const std::uint32_t version = le32(b.data() + 10), objects = le32(b.data() + 18);
    if (version == 1)
      return make("data", "nib", "compiled nib (NIBArchive, " + plural(objects, "object", "objects") + ")",
                  "nib:archive");
  }
  // CMS SignedData: SEQUENCE { OID 1.2.840.113549.1.7.2, ... }.
  static const unsigned char kSignedData[] = {0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02};
  if (b.size() > 16 && static_cast<std::uint8_t>(b[0]) == 0x30) {
    const unsigned l = static_cast<std::uint8_t>(b[1]);
    const std::size_t oid_at = l == 0x80 ? 2 : l < 0x80 ? 2 : 2 + (l & 0x7f);
    if (oid_at + sizeof kSignedData <= b.size() && std::memcmp(b.data() + oid_at, kSignedData, sizeof kSignedData) == 0) {
      if (contains(b, "<plist") || contains(b, "bplist00"))
        return make("data", "cms", "provisioning profile (CMS signed property list)", "mobileprovision");
      return make("data", "cms", "CMS signed data", "");
    }
  }
  if (b.size() >= 12 && static_cast<std::uint8_t>(b[0]) == 0xfa && static_cast<std::uint8_t>(b[1]) == 0xde &&
      static_cast<std::uint8_t>(b[2]) == 0x0c && static_cast<std::uint8_t>(b[3]) == 0xc0)
    return make("data", "codesign", "code signature (embedded signature SuperBlob)", "");
  // XML: "<?xml" or "<!DOCTYPE plist" or "<plist" first, a <plist element
  // in the head.
  const std::string text = ascii_head(b);
  std::size_t i = 0;
  while (i < text.size() && std::isspace(static_cast<unsigned char>(text[i]))) ++i;
  if (text.compare(i, 5, "<?xml") == 0 || text.compare(i, 9, "<!DOCTYPE") == 0 || text.compare(i, 6, "<plist") == 0) {
    if (text.find("<plist", i) != std::string::npos) {
      if (text.find("NSKeyedArchiver") != std::string::npos)
        return make("text", "plist", "XML property list (NSKeyedArchiver archive)", "keyed-archive");
      return make("text", "plist", "XML property list", "plist:xml");
    }
  }
  return std::nullopt;
}

}  // namespace revkit::container::detail
