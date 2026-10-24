// A small BER/DER reader (internal): what CMS signed data, X.509
// certificates' names and Apple's DER entitlements need. Definite and
// indefinite lengths, constructed strings; bounded depth and counts.
// Nothing is verified.
#pragma once

#include "revkit/apple/plist.hh"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace revkit::apple::detail {

struct Tlv {
  std::uint8_t cls = 0;  // 0 universal, 1 application, 2 context, 3 private
  bool constructed = false;
  std::uint32_t tag = 0;
  std::span<const std::byte> content;  // without an indefinite length's end marker
  std::size_t total = 0;               // header, content and end marker
  std::uint8_t first = 0;              // the identifier octet as written (tags < 31)
};

// The element at `at`. Error when it doesn't fit.
Tlv read_tlv(std::span<const std::byte> b, std::size_t at = 0, unsigned depth = 0);
// The elements of a constructed one's content, in order (at most 1 << 16).
std::vector<Tlv> children(const Tlv &t, unsigned depth = 0);
// A string's octets: a primitive one's content, or a constructed one's
// pieces joined.
std::string octets(const Tlv &t, unsigned depth = 0);
// An OID's dotted text ("1.2.840.113549.1.7.2").
std::string oid_text(std::span<const std::byte> content);

struct Certificate {
  std::string subject;      // "CN=..., OU=..., O=..., C=..."
  std::string common_name;  // the subject's CN
  std::string organizational_unit;
  std::string organization;
  std::string issuer;  // the issuer's CN
  std::string not_before, not_after;  // as written (UTCTime / GeneralizedTime)
};

struct SignedData {
  // The encapsulated content (absent for a detached signature, as a code
  // signature's is), and its type's OID.
  std::optional<std::string> content;
  std::string content_type;
  std::vector<Certificate> certificates;
  std::size_t signers = 0;
};

// A CMS ContentInfo holding SignedData (RFC 5652), read without checking
// any signature or certificate. Error when it isn't one.
SignedData read_signed_data(std::span<const std::byte> der);

// Apple's DER entitlements (a code signature's 0xfade7172 blob, without
// its 8-byte header) as a property list value.
Value der_plist(std::span<const std::byte> der);

}  // namespace revkit::apple::detail
