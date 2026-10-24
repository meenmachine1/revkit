// Embedded code signatures (LC_CODE_SIGNATURE) and provisioning profiles,
// as Apple's open-source Security framework (codesign's cs_blobs.h and
// the requirement language of reqreader/reqdumper) documents their
// layout; written from those descriptions, no code taken. Nothing is
// verified (codesign.hh).

#include "revkit/apple/codesign.hh"

#include "der.hh"
#include "text.hh"

#include <openssl/evp.h>

#include <cctype>
#include <cstdio>
#include <cstring>
#include <functional>

namespace revkit::apple {

namespace {

constexpr std::uint32_t kEmbeddedSignature = 0xfade0cc0;
constexpr std::uint32_t kCodeDirectory = 0xfade0c02;
constexpr std::uint32_t kRequirement = 0xfade0c00;
constexpr std::uint32_t kRequirements = 0xfade0c01;
constexpr std::uint32_t kBlobWrapper = 0xfade0b01;  // the CMS signature
constexpr std::uint32_t kEntitlements = 0xfade7171;
constexpr std::uint32_t kDerEntitlements = 0xfade7172;

struct Be {
  std::span<const std::byte> b;
  std::uint32_t u32(std::size_t at) const {
    if (at > b.size() || b.size() - at < 4) throw Error("a code signature read past its blob");
    return static_cast<std::uint32_t>(b[at]) << 24 | static_cast<std::uint32_t>(b[at + 1]) << 16 |
           static_cast<std::uint32_t>(b[at + 2]) << 8 | static_cast<std::uint32_t>(b[at + 3]);
  }
  std::uint64_t u64(std::size_t at) const { return static_cast<std::uint64_t>(u32(at)) << 32 | u32(at + 4); }
  std::uint8_t u8(std::size_t at) const {
    if (at >= b.size()) throw Error("a code signature read past its blob");
    return static_cast<std::uint8_t>(b[at]);
  }
  std::string cstr(std::size_t at) const {
    if (at >= b.size()) throw Error("a code signature string outside its blob");
    const char *p = reinterpret_cast<const char *>(b.data() + at);
    const std::size_t n = strnlen(p, b.size() - at);
    if (n == b.size() - at) throw Error("an unterminated code signature string");
    return valid_utf8(std::string_view(p, n));
  }
  static std::string valid_utf8(std::string_view s) { return detail::valid_utf8(s); }
};

std::string hex32(std::uint32_t v) {
  char buf[16];
  std::snprintf(buf, sizeof buf, "0x%x", v);
  return buf;
}

std::vector<std::string> cd_flags(std::uint32_t flags) {
  static const std::pair<std::uint32_t, const char *> kNames[] = {
      {0x1, "host"},           {0x2, "adhoc"},        {0x100, "hard"},         {0x200, "kill"},
      {0x400, "expires"},      {0x800, "restrict"},   {0x1000, "enforcement"}, {0x2000, "library-validation"},
      {0x10000, "runtime"},    {0x20000, "linker-signed"}};
  std::vector<std::string> out;
  std::uint32_t rest = flags;
  for (const auto &[bit, name] : kNames)
    if (flags & bit) {
      out.push_back(name);
      rest &= ~bit;
    }
  if (rest) out.push_back(hex32(rest));
  return out;
}

const char *kSpecialSlots[] = {"",         "info-plist",      "requirements",           "resources",
                               "application", "entitlements", "rep-specific",           "der-entitlements",
                               "launch-constraint-self", "launch-constraint-parent", "launch-constraint-responsible",
                               "library-constraint"};

std::string cdhash_of(std::span<const std::byte> cd, std::uint8_t type) {
  const EVP_MD *md = type == 1 ? EVP_sha1() : type == 2 || type == 3 ? EVP_sha256() : type == 4 ? EVP_sha384() : nullptr;
  if (!md) return "";
  unsigned char d[EVP_MAX_MD_SIZE];
  unsigned len = 0;
  if (EVP_Digest(cd.data(), cd.size(), d, &len, md, nullptr) != 1) return "";
  return detail::hex(std::as_bytes(std::span(d, std::min(len, 20u))));
}

CodeDirectory read_code_directory(std::span<const std::byte> blob, std::uint32_t slot, std::vector<std::string> &warnings) {
  Be r{blob};
  CodeDirectory cd;
  cd.slot = slot;
  cd.alternate = slot >= 0x1000 && slot < 0x1005;
  const std::uint32_t length = r.u32(4);
  if (length < 44 || length > blob.size()) throw Error("a CodeDirectory of bad length");
  const auto b = blob.first(length);
  Be c{b};
  cd.version = c.u32(8);
  cd.flags = c.u32(12);
  cd.flag_names = cd_flags(cd.flags);
  const std::uint32_t hash_offset = c.u32(16), ident_offset = c.u32(20);
  cd.special_slots = c.u32(24);
  cd.code_slots = c.u32(28);
  cd.code_limit = c.u32(32);
  cd.hash_size = c.u8(36);
  cd.hash_type = c.u8(37);
  cd.platform = c.u8(38);
  const std::uint8_t page = c.u8(39);
  cd.page_size = page == 0 ? 0 : page < 32 ? 1u << page : 0;
  static const char *kHashes[] = {"none", "sha1", "sha256", "sha256-truncated", "sha384"};
  cd.hash_name = cd.hash_type < 5 ? kHashes[cd.hash_type] : "type " + std::to_string(cd.hash_type);
  try {
    cd.identifier = c.cstr(ident_offset);
  } catch (const Error &e) {
    warnings.push_back(std::string("CodeDirectory identifier: ") + e.what());
  }
  if (cd.version >= 0x20200 && length >= 52) {
    const std::uint32_t team = c.u32(48);
    if (team != 0) {
      try {
        cd.team_id = c.cstr(team);
      } catch (const Error &e) {
        warnings.push_back(std::string("CodeDirectory team id: ") + e.what());
      }
    }
  }
  if (cd.version >= 0x20300 && length >= 64) {
    const std::uint64_t limit64 = c.u64(56);
    if (limit64) cd.code_limit = limit64;
  }
  if (cd.version >= 0x20400 && length >= 88) {
    cd.exec_seg_base = c.u64(64);
    cd.exec_seg_limit = c.u64(72);
    cd.exec_seg_flags = c.u64(80);
    static const std::pair<std::uint64_t, const char *> kExec[] = {
        {0x1, "main-binary"}, {0x10, "allow-unsigned"}, {0x20, "debugger"},       {0x40, "jit"},
        {0x80, "skip-lv"},    {0x100, "can-load-cdhash"}, {0x200, "can-exec-cdhash"}};
    for (const auto &[bit, name] : kExec)
      if (cd.exec_seg_flags & bit) cd.exec_seg_flag_names.push_back(name);
  }
  if (cd.version >= 0x20500 && length >= 92) cd.runtime_version = c.u32(88);
  // The special slots' hashes sit before hash_offset, slot n at -n.
  if (cd.hash_size > 0 && cd.hash_size <= 64)
    for (std::uint32_t s = 1; s <= std::min<std::uint32_t>(cd.special_slots, 64); ++s) {
      const std::uint64_t at = static_cast<std::uint64_t>(s) * cd.hash_size;
      if (at > hash_offset || hash_offset - at + cd.hash_size > length) break;
      const auto h = b.subspan(hash_offset - at, cd.hash_size);
      bool zero = true;
      for (std::byte x : h) zero = zero && x == std::byte{0};
      if (zero) continue;
      cd.special_hashes.push_back(s < std::size(kSpecialSlots) ? kSpecialSlots[s] : "slot " + std::to_string(s));
    }
  if (cd.hash_size > 0 && (static_cast<std::uint64_t>(cd.code_slots) * cd.hash_size > length ||
                           hash_offset > length - static_cast<std::uint64_t>(cd.code_slots) * cd.hash_size))
    warnings.push_back("the CodeDirectory's code hashes run past it");
  cd.cdhash = cdhash_of(b, cd.hash_type);
  return cd;
}

// ---- the requirement language ---------------------------------------------------

class RequirementPrinter {
 public:
  explicit RequirementPrinter(std::span<const std::byte> b) : b_(b) {}

  std::string run() {
    Be r{b_};
    if (r.u32(0) != kRequirement) throw Error("not a requirement blob");
    const std::uint32_t length = r.u32(4);
    if (length < 12 || length > b_.size()) throw Error("a requirement of bad length");
    b_ = b_.first(length);
    if (r.u32(8) != 1) throw Error("a requirement of unknown kind " + std::to_string(r.u32(8)));
    pos_ = 12;
    std::string out = expr(0, 0);
    return out;
  }

 private:
  enum Level { kOr = 0, kAnd = 1, kPrimary = 2 };

  std::uint32_t next() {
    const std::uint32_t v = Be{b_}.u32(pos_);
    pos_ += 4;
    return v;
  }
  std::string data() {
    const std::uint32_t n = next();
    if (n > b_.size() - pos_) throw Error("requirement data runs past its blob");
    std::string s(reinterpret_cast<const char *>(b_.data() + pos_), n);
    pos_ += (n + 3) & ~3u;
    if (pos_ > b_.size()) pos_ = b_.size();
    return s;
  }
  static std::string quoted(const std::string &s) {
    std::string out = "\"";
    for (char c : detail::valid_utf8(s)) {
      if (c == '"' || c == '\\') out += '\\';
      out += c;
    }
    return out + "\"";
  }
  static bool bare_ok(const std::string &s) {
    if (s.empty()) return false;
    for (char c : s)
      if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_' || c == '-')) return false;
    return !std::isdigit(static_cast<unsigned char>(s[0]));
  }
  std::string hash() {
    const std::string raw = data();
    return "H\"" + detail::hex(std::as_bytes(std::span(raw.data(), raw.size()))) + "\"";
  }
  std::string slot() {
    const std::int32_t s = static_cast<std::int32_t>(next());
    if (s == 0) return "leaf";
    if (s == -1) return "root";
    return std::to_string(s);
  }
  std::string oid() {
    const std::string raw = data();
    return detail::oid_text(std::as_bytes(std::span(raw.data(), raw.size())));
  }
  std::string match() {
    const std::uint32_t op = next();
    auto value = [&] { return quoted(data()); };
    auto stamp = [&] {
      const std::uint64_t t = static_cast<std::uint64_t>(next()) << 32 | next();
      return "timestamp \"" + iso8601(static_cast<double>(static_cast<std::int64_t>(t))) + "\"";
    };
    switch (op) {
      case 0: return " /* exists */";
      case 1: return " = " + value();
      case 2: return " ~ " + value();
      case 3: return " = " + value() + "*";
      case 4: return " = *" + value();
      case 5: return " < " + value();
      case 6: return " > " + value();
      case 7: return " <= " + value();
      case 8: return " >= " + value();
      case 9: return " = " + stamp();
      case 10: return " < " + stamp();
      case 11: return " > " + stamp();
      case 12: return " <= " + stamp();
      case 13: return " >= " + stamp();
      case 14: return " absent";
      default: throw Error("an unknown requirement match " + std::to_string(op));
    }
  }
  std::string key() {
    std::string k = data();
    return bare_ok(k) ? k : quoted(k);
  }

  std::string expr(int level, unsigned depth) {
    if (depth > 64) throw LimitError("a requirement nests too deep");
    if (++ops_ > 4096) throw LimitError("a requirement too long");
    const std::uint32_t op = next() & 0x00ffffff;
    auto wrap = [&](int mine, std::string s) { return mine < level ? "(" + s + ")" : s; };
    switch (op) {
      case 0: return "never";
      case 1: return "always";
      case 2: return "identifier " + quoted(data());
      case 3: return "anchor apple";
      case 4: {
        std::string s = slot();
        return "certificate " + s + " = " + hash();
      }
      case 5: {
        std::string k = key();
        return "info[" + k + "] = " + quoted(data());
      }
      case 6: {
        std::string a = expr(kAnd, depth + 1);
        std::string b = expr(kAnd, depth + 1);
        return wrap(kAnd, a + " and " + b);
      }
      case 7: {
        std::string a = expr(kOr, depth + 1);
        std::string b = expr(kOr, depth + 1);
        return wrap(kOr, a + " or " + b);
      }
      case 8: return "cdhash " + hash();
      case 9: return "! " + expr(kPrimary, depth + 1);
      case 10: {
        std::string k = key();
        return "info[" + k + "]" + match();
      }
      case 11: {
        std::string s = slot();
        std::string k = key();
        return "certificate " + s + "[" + k + "]" + match();
      }
      case 12: return "certificate " + slot() + " trusted";
      case 13: return "anchor trusted";
      case 14: {
        std::string s = slot();
        std::string o = oid();
        return "certificate " + s + "[field." + o + "]" + match();
      }
      case 15: return "anchor apple generic";
      case 16: {
        std::string k = key();
        return "entitlement[" + k + "]" + match();
      }
      case 17: {
        std::string s = slot();
        std::string o = oid();
        return "certificate " + s + "[policy." + o + "]" + match();
      }
      case 18: return "anchor apple " + data();
      case 19: return "(" + data() + ")";
      case 20: return "platform = " + std::to_string(next());
      case 21: return "notarized";
      case 22: {
        std::string s = slot();
        std::string o = oid();
        return "certificate " + s + "[timestamp." + o + "]" + match();
      }
      case 23: return "legacy";
      default: throw Error("an unknown requirement operator " + std::to_string(op));
    }
  }

  std::span<const std::byte> b_;
  std::size_t pos_ = 0;
  unsigned ops_ = 0;
};

Certificate cert_of(const detail::Certificate &c) {
  return Certificate{c.subject, c.common_name, c.organizational_unit, c.issuer, c.not_before, c.not_after};
}

}  // namespace

std::string requirement_text(std::span<const std::byte> blob) { return RequirementPrinter(blob).run(); }

CodeSignature parse_code_signature(std::span<const std::byte> blob) {
  Be r{blob};
  if (blob.size() < 12 || r.u32(0) != kEmbeddedSignature) throw Error("not an embedded code signature (0xfade0cc0)");
  const std::uint32_t length = r.u32(4), count = r.u32(8);
  if (length < 12 || length > blob.size()) throw Error("an embedded code signature of bad length");
  const auto b = blob.first(length);
  Be s{b};
  if (count > 256 || 12 + static_cast<std::uint64_t>(count) * 8 > length) throw Error("an embedded code signature with a bad blob count");
  CodeSignature out;
  for (std::uint32_t i = 0; i < count; ++i) {
    const std::uint32_t slot = s.u32(12 + i * 8), offset = s.u32(16 + i * 8);
    CodeSignature::Blob entry{slot, 0, offset, 0};
    if (offset > length - 8) {
      out.warnings.push_back("blob " + hex32(slot) + " is outside the signature");
      out.blobs.push_back(entry);
      continue;
    }
    entry.magic = s.u32(offset);
    entry.length = s.u32(offset + 4);
    out.blobs.push_back(entry);
    if (entry.length < 8 || entry.length > length - offset) {
      out.warnings.push_back("blob " + hex32(slot) + " runs past the signature");
      continue;
    }
    const auto sub = b.subspan(offset, entry.length);
    try {
      switch (entry.magic) {
        case kCodeDirectory: {
          CodeDirectory cd = read_code_directory(sub, slot, out.warnings);
          if (slot == 0) out.code_directories.insert(out.code_directories.begin(), std::move(cd));
          else out.code_directories.push_back(std::move(cd));
          break;
        }
        case kEntitlements: {
          out.entitlements_xml.assign(reinterpret_cast<const char *>(sub.data() + 8), sub.size() - 8);
          Limits l;
          l.max_input = 8u << 20;
          out.entitlements = parse(sub.subspan(8), l).root;
          break;
        }
        case kDerEntitlements:
          out.has_der_entitlements = true;
          out.der_entitlements = detail::der_plist(sub.subspan(8));
          break;
        case kRequirements: {
          Be q{sub};
          const std::uint32_t n = q.u32(8);
          if (n > 64 || 12 + static_cast<std::uint64_t>(n) * 8 > sub.size()) throw Error("a requirements set with a bad count");
          for (std::uint32_t k = 0; k < n; ++k) {
            Requirement req;
            req.type = q.u32(12 + k * 8);
            const std::uint32_t at = q.u32(16 + k * 8);
            static const char *kTypes[] = {"", "host", "guest", "designated", "library", "plugin"};
            req.type_name = req.type < 6 ? kTypes[req.type] : "type " + std::to_string(req.type);
            if (at > sub.size()) {
              out.warnings.push_back("requirement " + req.type_name + " is outside its set");
              continue;
            }
            try {
              req.text = requirement_text(sub.subspan(at));
            } catch (const Error &e) {
              out.warnings.push_back("requirement " + req.type_name + ": " + e.what());
            }
            out.requirements.push_back(std::move(req));
          }
          break;
        }
        case kBlobWrapper:
          out.cms_size = entry.length - 8;
          out.has_cms = entry.length > 8;
          if (out.has_cms) {
            try {
              const detail::SignedData sd = detail::read_signed_data(sub.subspan(8));
              for (const auto &c : sd.certificates) out.certificates.push_back(cert_of(c));
            } catch (const Error &e) {
              out.warnings.push_back(std::string("CMS signature: ") + e.what());
            }
          }
          break;
        default:
          break;
      }
    } catch (const Error &e) {
      out.warnings.push_back("blob " + hex32(slot) + ": " + e.what());
    }
  }
  if (out.code_directories.empty()) out.warnings.push_back("no CodeDirectory");
  else out.adhoc = (out.code_directories.front().flags & 0x2) != 0;
  return out;
}

std::optional<SignatureRange> find_code_signature(
    const std::function<std::vector<std::byte>(std::uint64_t, std::size_t)> &read, std::uint64_t file_size) {
  auto word = [](const std::vector<std::byte> &b, std::size_t at, bool be) -> std::uint32_t {
    if (at + 4 > b.size()) throw Error("a Mach-O header read past its end");
    const auto u = [&](std::size_t i) { return static_cast<std::uint32_t>(b[at + i]); };
    return be ? u(0) << 24 | u(1) << 16 | u(2) << 8 | u(3) : u(3) << 24 | u(2) << 16 | u(1) << 8 | u(0);
  };
  try {
    const std::vector<std::byte> head = read(0, 4096);
    if (head.size() < 32) return std::nullopt;
    std::uint64_t slice = 0;
    const std::uint32_t magic_be = word(head, 0, true);
    if (magic_be == 0xcafebabe || magic_be == 0xcafebabf) {
      const bool wide = magic_be == 0xcafebabf;
      const std::uint32_t n = word(head, 4, true);
      if (n == 0 || n > 64) return std::nullopt;
      const std::size_t each = wide ? 32 : 20;
      std::optional<std::uint64_t> arm, x86, first;
      for (std::uint32_t i = 0; i < n; ++i) {
        const std::size_t at = 8 + i * each;
        const std::uint32_t cpu = word(head, at, true);
        const std::uint64_t off = wide ? static_cast<std::uint64_t>(word(head, at + 8, true)) << 32 | word(head, at + 12, true)
                                       : word(head, at + 8, true);
        if (off >= file_size) continue;
        if (!first) first = off;
        if (cpu == 0x0100000c && !arm) arm = off;
        if (cpu == 0x01000007 && !x86) x86 = off;
      }
      if (!first) return std::nullopt;
      slice = arm ? *arm : x86 ? *x86 : *first;
    }
    const std::vector<std::byte> h = slice == 0 ? head : read(slice, 32);
    if (h.size() < 28) return std::nullopt;
    const std::uint32_t m = word(h, 0, false);
    bool be;
    if (m == 0xfeedface || m == 0xfeedfacf) be = false;
    else if (m == 0xcefaedfe || m == 0xcffaedfe) be = true;
    else return std::nullopt;
    const bool wide = m == 0xfeedfacf || m == 0xcffaedfe;
    const std::uint32_t ncmds = word(h, 16, be), sizeofcmds = word(h, 20, be);
    if (ncmds > 65536 || sizeofcmds > (16u << 20)) return std::nullopt;
    const std::size_t start = wide ? 32 : 28;
    const std::vector<std::byte> cmds = read(slice + start, sizeofcmds);
    std::size_t at = 0;
    for (std::uint32_t i = 0; i < ncmds && at + 8 <= cmds.size(); ++i) {
      const std::uint32_t cmd = word(cmds, at, be), size = word(cmds, at + 4, be);
      if (size < 8) return std::nullopt;
      if (cmd == 0x1d && at + 16 <= cmds.size()) {
        SignatureRange r;
        r.slice_offset = slice;
        r.offset = slice + word(cmds, at + 8, be);
        r.size = word(cmds, at + 12, be);
        if (r.offset > file_size || r.size > file_size - r.offset) return std::nullopt;
        return r;
      }
      at += size;
    }
  } catch (const Error &) {
  }
  return std::nullopt;
}

const Value *entitlements_of(const CodeSignature &sig) {
  if (sig.entitlements) return &*sig.entitlements;
  if (sig.der_entitlements) return &*sig.der_entitlements;
  return nullptr;
}

ProvisioningProfile parse_provisioning_profile(std::span<const std::byte> der, const Limits &limits) {
  const detail::SignedData sd = detail::read_signed_data(der);
  if (!sd.content) throw Error("CMS signed data without content (not a provisioning profile)");
  ProvisioningProfile p;
  p.plist = parse(std::as_bytes(std::span(*sd.content)), limits).root;
  if (!p.plist.is(Value::Type::dict)) throw Error("a provisioning profile whose plist isn't a dictionary");
  for (const auto &c : sd.certificates) p.signer_certificates.push_back(cert_of(c));
  const Value &v = p.plist;
  p.name = v.string_at("Name");
  p.uuid = v.string_at("UUID");
  p.app_id_name = v.string_at("AppIDName");
  p.team_identifiers = v.strings_at("TeamIdentifier");
  p.team_name = v.string_at("TeamName");
  p.platforms = v.strings_at("Platform");
  if (const Value *d = v.get("CreationDate"); d && d->is(Value::Type::date)) p.creation_date = d->real;
  if (const Value *d = v.get("ExpirationDate"); d && d->is(Value::Type::date)) p.expiration_date = d->real;
  if (const Value *d = v.get("ProvisionedDevices"); d && d->is(Value::Type::array)) p.provisioned_devices = d->array.size();
  if (const Value *d = v.get("ProvisionsAllDevices")) p.provisions_all_devices = d->as_bool().value_or(false);
  if (const Value *d = v.get("DeveloperCertificates"); d && d->is(Value::Type::array)) p.developer_certificates = d->array.size();
  if (const Value *e = v.get("Entitlements"); e && e->is(Value::Type::dict)) {
    p.entitlements = *e;
    p.application_identifier = e->string_at("application-identifier");
    if (p.application_identifier.empty()) p.application_identifier = e->string_at("com.apple.application-identifier");
    p.get_task_allow = e->get("get-task-allow") && e->get("get-task-allow")->as_bool().value_or(false);
  }
  // Xcode's own rule of thumb: debugging allowed is development; devices
  // listed without it, ad hoc; all devices, enterprise; else App Store.
  p.kind = p.get_task_allow           ? "development"
           : p.provisions_all_devices ? "enterprise"
           : p.provisioned_devices    ? "ad-hoc"
                                      : "app-store";
  return p;
}

}  // namespace revkit::apple
