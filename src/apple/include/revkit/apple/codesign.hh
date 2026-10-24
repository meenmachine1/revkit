// Code signatures and provisioning profiles (docs/apple-apps.md), read as
// data. NOTHING HERE VERIFIES A SIGNATURE: no hash is checked against the
// code, no CMS signature against its certificates, no certificate against
// a trust anchor. What a file says about itself is reported as it says it.
//
//   parse_code_signature()  LC_CODE_SIGNATURE's blob: an embedded
//                           signature SuperBlob (0xfade0cc0) and its
//                           CodeDirectories (identifier, team, flags,
//                           hashes), entitlements (XML and DER), the
//                           requirements (decompiled to their text), and
//                           the CMS signature's certificates' names
//   parse_provisioning_profile()  embedded.mobileprovision: the CMS
//                           signed plist inside, and what it says
#pragma once

#include "revkit/apple/plist.hh"

#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace revkit::apple {

struct CodeDirectory {
  std::uint32_t version = 0;
  std::uint32_t flags = 0;
  // codesign's names for the flags: "adhoc", "hard", "kill", "expires",
  // "restrict", "enforcement", "library-validation", "runtime" (the
  // hardened runtime), "linker-signed"; unknown bits as hex.
  std::vector<std::string> flag_names;
  std::string identifier;
  std::string team_id;  // version 0x20200 and later
  std::uint8_t hash_type = 0;
  std::string hash_name;  // "sha1", "sha256", "sha256-truncated", "sha384"
  std::uint8_t hash_size = 0;
  std::uint32_t page_size = 0;  // 0: the whole file is one page
  std::uint32_t code_slots = 0;
  std::uint32_t special_slots = 0;
  std::uint64_t code_limit = 0;
  std::uint8_t platform = 0;
  // Which special slots hold a hash: "info-plist", "requirements",
  // "resources", "application", "entitlements", "der-entitlements",
  // "launch-constraint-self", ...
  std::vector<std::string> special_hashes;
  // The executable segment (version 0x20400): base, limit and flags
  // ("main-binary", "allow-unsigned", "debugger", "jit", "skip-lv",
  // "can-load-cdhash", "can-exec-cdhash").
  std::uint64_t exec_seg_base = 0, exec_seg_limit = 0, exec_seg_flags = 0;
  std::vector<std::string> exec_seg_flag_names;
  std::uint32_t runtime_version = 0;  // 0x20500: the SDK the hardened runtime targets
  // The CodeDirectory's hash with its own hash type, as `codesign -dv`'s
  // CDHash prints it (20 bytes, hex). Computed, not checked against
  // anything.
  std::string cdhash;
  bool alternate = false;  // an alternate CodeDirectory (slot 0x1000+)
  std::uint32_t slot = 0;
};

struct Requirement {
  std::uint32_t type = 0;
  std::string type_name;  // "host", "guest", "designated", "library", "plugin"
  std::string text;       // the requirement language, as `codesign -d -r-` prints it
};

struct Certificate {
  std::string subject;     // "CN=Apple Development: ..., OU=ABCDE12345, O=..., C=US"
  std::string common_name;
  std::string organizational_unit;  // a developer certificate's team id
  std::string issuer;      // the issuer's CN
  std::string not_before, not_after;
};

struct CodeSignature {
  std::vector<CodeDirectory> code_directories;  // the primary first
  // The XML entitlements blob as written, and parsed.
  std::string entitlements_xml;
  std::optional<Value> entitlements;
  // The DER entitlements blob (0xfade7172), parsed.
  bool has_der_entitlements = false;
  std::optional<Value> der_entitlements;
  std::vector<Requirement> requirements;
  // The CMS signature blob (0xfade0b01): present and not empty, its size,
  // and its certificates (leaf first, as written). An ad-hoc signature has
  // none.
  bool has_cms = false;
  std::uint32_t cms_size = 0;
  std::vector<Certificate> certificates;
  bool adhoc = false;
  // Every blob of the SuperBlob: slot, magic, offset, size.
  struct Blob {
    std::uint32_t slot = 0;
    std::uint32_t magic = 0;
    std::uint32_t offset = 0;
    std::uint32_t length = 0;
  };
  std::vector<Blob> blobs;
  std::vector<std::string> warnings;
};

// LC_CODE_SIGNATURE's bytes (the dataoff/datasize range). Error when it
// isn't an embedded signature SuperBlob; problems inside one are warnings.
CodeSignature parse_code_signature(std::span<const std::byte> blob);

// Where a Mach-O file's LC_CODE_SIGNATURE data is, in the file: a thin
// file's, or a universal file's default slice's (the first arm64 or
// arm64e one, else x86_64, else the first, as revkit's loader picks).
// `read(offset, n)` returns up to n bytes of the file. nullopt when it
// isn't a Mach-O or has no signature.
struct SignatureRange {
  std::uint64_t offset = 0;
  std::uint32_t size = 0;
  std::uint64_t slice_offset = 0;
};
std::optional<SignatureRange> find_code_signature(
    const std::function<std::vector<std::byte>(std::uint64_t, std::size_t)> &read, std::uint64_t file_size);

// The entitlements: XML when present, else DER; null when neither.
const Value *entitlements_of(const CodeSignature &sig);

// A requirement blob (0xfade0c00) as text. Error when malformed.
std::string requirement_text(std::span<const std::byte> blob);

struct ProvisioningProfile {
  Value plist;  // the whole plist
  std::string name;
  std::string uuid;
  std::string app_id_name;
  std::string application_identifier;  // Entitlements' application-identifier
  std::vector<std::string> team_identifiers;
  std::string team_name;
  std::vector<std::string> platforms;
  std::optional<double> creation_date, expiration_date;  // CFAbsoluteTime
  std::size_t provisioned_devices = 0;
  bool provisions_all_devices = false;  // enterprise
  bool get_task_allow = false;
  // "development", "ad-hoc", "enterprise", "app-store", from the above.
  std::string kind;
  std::optional<Value> entitlements;
  std::size_t developer_certificates = 0;
  std::vector<Certificate> signer_certificates;  // the CMS wrapper's
  std::vector<std::string> warnings;
};

// embedded.mobileprovision (and .provisionprofile): CMS signed data
// holding a plist. Error when it isn't one.
ProvisioningProfile parse_provisioning_profile(std::span<const std::byte> der, const Limits &limits = {});

}  // namespace revkit::apple
