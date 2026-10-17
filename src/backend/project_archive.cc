#include "project_archive.h"

#include "diff_session.h"
#include "revkit/analysis/memory.h"
#include "revkit/analysis/units.h"
#include "revkit/analysis/user_refs.h"
#include "revkit/analysis/register_values.h"
#include "data_settings.h"
#include "type_archive.h"
#include "type_record.h"
#include "revkit/cparse/archive.h"

#include <google/protobuf/util/json_util.h>
#include <openssl/evp.h>
#include <zlib.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <set>
#include <unordered_map>

namespace revkit::backend::archive {
namespace {

constexpr std::size_t kBlock = 512;
constexpr std::string_view kLogMagic = "RKLOG1\n";
constexpr std::uint64_t kMaxTarSize = (std::uint64_t{1} << 33) - 1;  // 11 octal digits
constexpr std::size_t kMaxSub = 4096;
constexpr std::size_t kMaxShortText = 4096;

std::uint64_t Padded(std::uint64_t n) { return (n + kBlock - 1) / kBlock * kBlock; }

bool IsHex64(std::string_view s) {
  if (s.size() != 64) return false;
  for (char c : s)
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
  return true;
}

class Sha256 {
 public:
  Sha256() : ctx_(EVP_MD_CTX_new()) { EVP_DigestInit_ex(ctx_, EVP_sha256(), nullptr); }
  ~Sha256() { EVP_MD_CTX_free(ctx_); }
  Sha256(const Sha256 &) = delete;
  Sha256 &operator=(const Sha256 &) = delete;
  void update(std::string_view s) { EVP_DigestUpdate(ctx_, s.data(), s.size()); }
  std::string hex() {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    EVP_DigestFinal_ex(ctx_, md, &len);
    static const char *digits = "0123456789abcdef";
    std::string out;
    for (unsigned i = 0; i < len; ++i) {
      out += digits[md[i] >> 4];
      out += digits[md[i] & 15];
    }
    return out;
  }

 private:
  EVP_MD_CTX *ctx_;
};

Error Invalid(std::string m) { return Error{"invalid project archive: " + std::move(m), false}; }

// The ustar header for a regular file.
std::string TarHeader(std::string_view path, std::uint64_t size) {
  std::string h(kBlock, '\0');
  std::memcpy(h.data(), path.data(), path.size());
  auto octal = [&](std::size_t at, std::size_t width, std::uint64_t v) {
    // width - 1 digits and a NUL.
    for (std::size_t i = width - 1; i-- > 0;) {
      h[at + i] = static_cast<char>('0' + (v & 7));
      v >>= 3;
    }
  };
  octal(100, 8, 0644);
  octal(108, 8, 0);
  octal(116, 8, 0);
  octal(124, 12, size);
  octal(136, 12, 0);  // mtime: none, so equal archives are equal bytes
  h[156] = '0';
  std::memcpy(h.data() + 257, "ustar\0" "00", 8);
  std::memset(h.data() + 148, ' ', 8);
  unsigned sum = 0;
  for (unsigned char c : h) sum += c;
  char buf[8];
  std::snprintf(buf, sizeof buf, "%06o", sum);
  std::memcpy(h.data() + 148, buf, 6);
  h[154] = '\0';
  h[155] = ' ';
  return h;
}

std::optional<std::uint64_t> ParseOctal(const char *p, std::size_t n) {
  std::size_t i = 0;
  while (i < n && p[i] == ' ') ++i;
  std::uint64_t v = 0;
  std::size_t digits = 0;
  for (; i < n && p[i] >= '0' && p[i] <= '7'; ++i, ++digits) {
    if (v > (UINT64_MAX >> 3)) return std::nullopt;
    v = (v << 3) | static_cast<std::uint64_t>(p[i] - '0');
  }
  if (digits == 0) return std::nullopt;
  for (; i < n; ++i)
    if (p[i] != ' ' && p[i] != '\0') return std::nullopt;
  return v;
}

// Inflates a gzip stream from a Source, never past a budget of output
// bytes (the decompression-bomb guard: the budget is what the manifest
// declares).
class Inflater {
 public:
  explicit Inflater(const Source &src) : src_(src), in_(1 << 16, '\0') {
    std::memset(&z_, 0, sizeof z_);
    ok_ = inflateInit2(&z_, 15 + 16) == Z_OK;
  }
  ~Inflater() {
    if (ok_) inflateEnd(&z_);
  }
  void set_budget(std::uint64_t total) { budget_ = total; }
  std::uint64_t produced() const { return produced_; }

  // Reads exactly n bytes; false (and `error`) at the end of the stream,
  // on a corrupt stream or past the budget.
  bool read(char *out, std::size_t n, std::string &error) {
    if (!ok_) {
      error = "cannot start decompressing";
      return false;
    }
    if (produced_ + n > budget_) {
      error = "it holds more data than its manifest declares";
      return false;
    }
    z_.next_out = reinterpret_cast<Bytef *>(out);
    z_.avail_out = static_cast<uInt>(n);
    while (z_.avail_out > 0) {
      if (ended_) {
        error = "it ends early";
        return false;
      }
      if (z_.avail_in == 0) {
        const std::size_t got = src_(in_.data(), in_.size());
        if (got == 0) {
          error = "it ends early (truncated)";
          return false;
        }
        z_.next_in = reinterpret_cast<Bytef *>(in_.data());
        z_.avail_in = static_cast<uInt>(got);
      }
      const int rc = inflate(&z_, Z_NO_FLUSH);
      if (rc == Z_STREAM_END) {
        ended_ = true;
      } else if (rc != Z_OK && rc != Z_BUF_ERROR) {
        error = std::string("it is not a gzip stream or is corrupt (") + (z_.msg ? z_.msg : "zlib error") + ")";
        return false;
      } else if (rc == Z_BUF_ERROR && z_.avail_in != 0) {
        error = "it is corrupt (zlib made no progress)";
        return false;
      }
    }
    produced_ += n;
    return true;
  }

 private:
  const Source &src_;
  std::string in_;
  z_stream z_;
  bool ok_ = false, ended_ = false;
  std::uint64_t budget_ = 0, produced_ = 0;
};

struct Header {
  std::string name;
  std::uint64_t size = 0;
  bool end = false;  // a zero block
};

std::optional<Error> ReadHeader(Inflater &in, Header &h) {
  char b[kBlock];
  std::string why;
  if (!in.read(b, kBlock, why)) return Invalid(why);
  if (std::all_of(b, b + kBlock, [](char c) { return c == 0; })) {
    h.end = true;
    return std::nullopt;
  }
  unsigned sum = 0;
  for (std::size_t i = 0; i < kBlock; ++i) sum += (i >= 148 && i < 156) ? ' ' : static_cast<unsigned char>(b[i]);
  auto stored = ParseOctal(b + 148, 8);
  if (!stored || *stored != sum) return Invalid("a tar header's checksum is wrong");
  if (std::memcmp(b + 257, "ustar", 5) != 0) return Invalid("a member is not a ustar entry");
  if (b[156] != '0' && b[156] != '\0') return Invalid("a member is not a regular file (links, directories and devices are refused)");
  if (b[345] != '\0') return Invalid("a member's name uses the ustar prefix field");
  std::size_t len = 0;
  while (len < 100 && b[len] != '\0') ++len;
  h.name.assign(b, len);
  auto size = ParseOctal(b + 124, 12);
  if (!size) return Invalid("a member's size is malformed");
  h.size = *size;
  return std::nullopt;
}

bool ParseManifestJson(std::string_view json, bool strict, pb::ProjectArchiveManifest &m) {
  google::protobuf::util::JsonParseOptions o;
  o.ignore_unknown_fields = !strict;
  m.Clear();
  return google::protobuf::util::JsonStringToMessage(std::string(json), &m, o).ok();
}

bool ValidKey(const facts::FactKey &k) {
  const auto kind = static_cast<std::uint16_t>(k.kind);
  return kind >= static_cast<std::uint16_t>(facts::FactKind::Name) &&
         kind <= static_cast<std::uint16_t>(facts::FactKind::RegisterValue) && k.sub.size() <= kMaxSub;
}

}  // namespace

bool ValidName(std::string_view name) {
  if (name.empty() || name.size() > 200) return false;
  for (unsigned char c : name)
    if (c < 0x20 || c == 0x7f || c == '/') return false;
  return true;
}

bool ValidFolderPath(std::string_view path) {
  if (path == "/") return true;
  if (path.empty() || path.front() != '/' || path.back() == '/' || path.size() > 4096) return false;
  std::size_t at = 1;
  while (at <= path.size()) {
    std::size_t next = path.find('/', at);
    if (next == std::string_view::npos) next = path.size();
    std::string_view part = path.substr(at, next - at);
    if (!ValidName(part) || part == "." || part == "..") return false;
    at = next + 1;
  }
  return true;
}

// --- Writer -----------------------------------------------------------------

struct Writer::Z {
  z_stream s;
};

Writer::Writer(Sink sink, int level) : z_(std::make_unique<Z>()), sink_(std::move(sink)) {
  std::memset(&z_->s, 0, sizeof z_->s);
  ok_ = deflateInit2(&z_->s, level, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) == Z_OK;
}

Writer::~Writer() { deflateEnd(&z_->s); }

bool Writer::deflate_out(std::string_view in, int flush) {
  if (!ok_) return false;
  char out[1 << 16];
  z_->s.next_in = reinterpret_cast<Bytef *>(const_cast<char *>(in.data()));
  z_->s.avail_in = static_cast<uInt>(in.size());
  do {
    z_->s.next_out = reinterpret_cast<Bytef *>(out);
    z_->s.avail_out = sizeof out;
    const int rc = deflate(&z_->s, flush);
    if (rc == Z_STREAM_ERROR) return ok_ = false;
    const std::size_t n = sizeof out - z_->s.avail_out;
    if (n) {
      out_bytes_ += n;
      if (!sink_(std::string_view(out, n))) return ok_ = false;
    }
    if (flush == Z_FINISH && rc == Z_STREAM_END) break;
  } while (z_->s.avail_out == 0 || (flush == Z_FINISH));
  return ok_;
}

bool Writer::begin_file(std::string_view path, std::uint64_t size) {
  if (!ok_ || in_file_ || path.empty() || path.size() >= 100 || size > kMaxTarSize) return ok_ = false;
  in_file_ = true;
  remaining_ = size;
  written_ = size;
  return deflate_out(TarHeader(path, size), Z_NO_FLUSH);
}

bool Writer::write(std::string_view data) {
  if (!ok_ || !in_file_ || data.size() > remaining_) return ok_ = false;
  remaining_ -= data.size();
  // deflate takes at most 4 GiB at once.
  while (!data.empty()) {
    const std::size_t n = std::min<std::size_t>(data.size(), 1u << 30);
    if (!deflate_out(data.substr(0, n), Z_NO_FLUSH)) return false;
    data.remove_prefix(n);
  }
  return true;
}

bool Writer::end_file() {
  if (!ok_ || !in_file_ || remaining_ != 0) return ok_ = false;
  in_file_ = false;
  const std::uint64_t pad = Padded(written_) - written_;
  if (pad) return deflate_out(std::string(pad, '\0'), Z_NO_FLUSH);
  return true;
}

bool Writer::finish() {
  if (!ok_ || in_file_) return ok_ = false;
  return deflate_out(std::string(2 * kBlock, '\0'), Z_FINISH);
}

std::string LogHeader() { return std::string(kLogMagic); }

void AppendLogOp(std::string &out, const facts::Op &op) {
  const std::string enc = facts::encode_to_string(op);
  facts::Encoder e;
  e.varint(enc.size());
  out += e.str();
  out += enc;
}

std::string ManifestJson(const pb::ProjectArchiveManifest &m) {
  google::protobuf::util::JsonPrintOptions o;
  o.add_whitespace = true;
  o.preserve_proto_field_names = true;
  std::string out;
  (void)google::protobuf::util::MessageToJsonString(m, &out, o);
  return out;
}

// --- Reading ----------------------------------------------------------------

std::optional<Error> ValidateManifest(const pb::ProjectArchiveManifest &m, const Limits &limits) {
  if (m.format() != kFormat) return Error{"not a revkit project archive (format \"" + m.format() + "\")", true};
  if (m.format_version() == 0) return Invalid("format_version is missing");
  if (m.format_version() > kFormatVersion)
    return Error{"project archive format version " + std::to_string(m.format_version()) +
                     " is newer than this revkit reads (" + std::to_string(kFormatVersion) +
                     "); open it with a newer revkit",
                 true};
  if (m.op_format() != kOpFormat)
    return Error{"the archive's ops are in encoding " + std::to_string(m.op_format()) + ", this revkit reads " +
                     std::to_string(kOpFormat),
                 true};
  if (m.project_name().size() > 200) return Invalid("project_name is longer than 200 characters");
  if (m.created_by().size() > kMaxShortText) return Invalid("created_by is too long");
  if (static_cast<std::uint64_t>(m.programs_size()) > limits.max_programs)
    return Invalid("it has more than " + std::to_string(limits.max_programs) + " programs");
  if (static_cast<std::uint64_t>(m.folders_size()) > limits.max_folders)
    return Invalid("it has more than " + std::to_string(limits.max_folders) + " folders");
  std::set<std::string> folders{"/"};
  for (const std::string &f : m.folders()) {
    if (f == "/" || !ValidFolderPath(f)) return Invalid("bad folder path \"" + f.substr(0, 300) + "\"");
    const std::string parent = f.substr(0, std::max<std::size_t>(1, f.rfind('/')));
    if (!folders.contains(parent)) return Invalid("folder " + f + " comes before its parent");
    if (!folders.insert(f).second) return Invalid("folder " + f + " is listed twice");
  }
  const auto &log = m.log();
  if (log.path() != kLogPath) return Invalid("the log is not log.bin");
  if (log.size() > limits.max_log_bytes || log.size() > kMaxTarSize) return Invalid("log.bin is over the size limit");
  if (!IsHex64(log.sha256())) return Invalid("log.bin's sha256 is malformed");
  if (log.count() > limits.max_ops) return Invalid("log.bin has too many ops");
  std::uint64_t total = log.size();
  std::set<std::uint32_t> ordinals;
  for (int i = 0; i < m.programs_size(); ++i) {
    const pb::ArchiveProgram &p = m.programs(i);
    const std::string key = "p" + std::to_string(i);
    if (p.key() != key) return Invalid("program " + std::to_string(i) + " should have key " + key);
    if (!ValidName(p.name())) return Invalid("program " + key + " has a bad name");
    if (p.program_id().size() > kMaxShortText || p.format().size() > kMaxShortText ||
        p.language_id().size() > kMaxShortText)
      return Invalid("program " + key + ": a field is too long");
    if (!IsHex64(p.sha256())) return Invalid("program " + key + "'s sha256 is malformed");
    if (p.size() == 0 || p.size() > limits.max_program_bytes || p.size() > kMaxTarSize)
      return Invalid("program " + key + "'s size is 0 or over the limit");
    if (!folders.contains(p.folder())) return Invalid("program " + key + " is in a folder the manifest doesn't list");
    if (p.ordinal() >= kMaxOrdinals || !ordinals.insert(p.ordinal()).second)
      return Invalid("program " + key + " has a bad or repeated ordinal");
    if (p.has_binary() == m.annotations_only())
      return Invalid(m.annotations_only() ? "an annotations-only archive holds program " + key + "'s bytes"
                                          : "program " + key + "'s bytes are missing");
    if (p.has_binary()) total += p.size();
    if (static_cast<std::uint64_t>(p.regions_size()) > limits.max_regions)
      return Invalid("program " + key + " has too many memory-region files");
    std::vector<std::pair<std::uint64_t, std::uint64_t>> spans;
    std::set<std::string> shas;
    for (const pb::ArchiveFile &r : p.regions()) {
      if (!IsHex64(r.sha256()) || !shas.insert(r.sha256()).second)
        return Invalid("program " + key + " has a bad or repeated region sha256");
      if (r.path() != "programs/" + key + "/regions/" + r.sha256() + ".bin")
        return Invalid("program " + key + " has a region at an unexpected path");
      if (r.size() == 0 || r.size() > limits.max_region_bytes || r.size() > kMaxTarSize)
        return Invalid("program " + key + " has a region over the size limit");
      if (r.offset() < p.size() || r.offset() + r.size() < r.offset())
        return Invalid("program " + key + " has a region at a bad offset");
      spans.emplace_back(r.offset(), r.offset() + r.size());
      total += r.size();
    }
    std::sort(spans.begin(), spans.end());
    for (std::size_t j = 1; j < spans.size(); ++j)
      if (spans[j].first < spans[j - 1].second) return Invalid("program " + key + " has overlapping regions");
    if (total > limits.max_total_bytes) break;
  }
  if (total > limits.max_total_bytes)
    return Invalid("it declares more than " + std::to_string(limits.max_total_bytes >> 20) + " MiB");
  return std::nullopt;
}

std::optional<Error> ReadArchive(const Source &source, const Limits &limits, pb::ProjectArchiveManifest &manifest,
                                 MemberSink &sink) {
  Inflater in(source);
  in.set_budget(kBlock + Padded(limits.max_manifest_bytes));
  Header h;
  if (auto e = ReadHeader(in, h)) return e;
  if (h.end || h.name != kManifestPath) return Invalid("its first member is not manifest.json");
  if (h.size > limits.max_manifest_bytes) return Invalid("manifest.json is over the size limit");
  std::string json(Padded(h.size), '\0');
  std::string why;
  if (!in.read(json.data(), json.size(), why)) return Invalid(why);
  json.resize(h.size);
  // The version first, leniently, so a newer archive is told apart from a
  // broken one; then the whole manifest, strictly.
  pb::ProjectArchiveManifest loose;
  if (!ParseManifestJson(json, false, loose)) return Invalid("manifest.json is not a valid manifest");
  if (auto e = ValidateManifest(loose, limits); e && e->unsupported) return e;
  if (!ParseManifestJson(json, true, manifest)) return Invalid("manifest.json has fields this revkit doesn't know");
  if (auto e = ValidateManifest(manifest, limits)) return e;

  std::map<std::string, Member> expected;
  std::map<std::string, std::string> sha;
  std::uint64_t budget = in.produced();
  auto expect = [&](const std::string &path, Member m, const std::string &hash) {
    budget += kBlock + Padded(m.size);
    sha[path] = hash;
    expected.emplace(path, m);
  };
  expect(std::string(kLogPath), Member{Member::kLog, -1, -1, manifest.log().size()}, manifest.log().sha256());
  for (int i = 0; i < manifest.programs_size(); ++i) {
    const pb::ArchiveProgram &p = manifest.programs(i);
    if (p.has_binary())
      expect("programs/" + p.key() + "/program.bin", Member{Member::kProgram, i, -1, p.size()}, p.sha256());
    // Regions' bytes are part of the work: in annotations-only archives too.
    for (int j = 0; j < p.regions_size(); ++j)
      expect(p.regions(j).path(), Member{Member::kRegion, i, j, p.regions(j).size()}, p.regions(j).sha256());
  }
  in.set_budget(budget + kBlock);  // and the end-of-archive block
  std::set<std::string> seen;
  std::string buf(1 << 16, '\0');
  while (seen.size() < expected.size()) {
    if (auto e = ReadHeader(in, h)) return e;
    if (h.end) {
      for (const auto &[path, m] : expected)
        if (!seen.contains(path)) return Invalid(path + " is missing");
      return Invalid("it ends early");
    }
    auto it = expected.find(h.name);
    if (it == expected.end())
      return Invalid(h.name == kManifestPath ? "manifest.json appears twice"
                                             : "it holds a member its manifest doesn't declare");
    if (!seen.insert(h.name).second) return Invalid(h.name + " appears twice");
    if (h.size != it->second.size) return Invalid(h.name + " is not the size its manifest declares");
    sink.begin(it->second);
    Sha256 hash;
    for (std::uint64_t left = h.size; left > 0;) {
      const std::size_t n = static_cast<std::size_t>(std::min<std::uint64_t>(left, buf.size()));
      if (!in.read(buf.data(), n, why)) {
        sink.end(false);
        return Invalid(why);
      }
      hash.update(std::string_view(buf.data(), n));
      sink.data(std::string_view(buf.data(), n));
      left -= n;
    }
    const std::uint64_t pad = Padded(h.size) - h.size;
    if (pad && !in.read(buf.data(), static_cast<std::size_t>(pad), why)) {
      sink.end(false);
      return Invalid(why);
    }
    if (hash.hex() != sha[h.name]) {
      sink.end(false);
      return Invalid(h.name + " doesn't match its sha256");
    }
    sink.end(true);
  }
  if (auto e = ReadHeader(in, h)) return e;
  if (!h.end) return Invalid("it holds a member its manifest doesn't declare");
  return std::nullopt;
}

std::optional<Error> DecodeLog(std::string_view data, const Limits &limits, std::vector<facts::Op> &out) {
  out.clear();
  if (!data.starts_with(kLogMagic)) return Invalid("log.bin doesn't start with its header");
  facts::Decoder d(data.substr(kLogMagic.size()));
  try {
    while (!d.done()) {
      if (out.size() >= limits.max_ops) return Invalid("log.bin has too many ops");
      const std::uint64_t n = d.varint();
      if (n > limits.max_op_bytes || n > d.remaining()) return Invalid("log.bin op " + std::to_string(out.size()) + " is too long");
      std::string_view enc = d.raw(static_cast<std::size_t>(n));
      out.push_back(facts::decode_from_string<facts::Op>(enc));
    }
  } catch (const facts::DecodeError &e) {
    return Invalid("log.bin op " + std::to_string(out.size()) + " can't be decoded: " + e.what());
  } catch (const std::exception &e) {
    return Invalid("log.bin op " + std::to_string(out.size()) + " can't be decoded: " + e.what());
  }
  return std::nullopt;
}

// --- Ops ----------------------------------------------------------------------

std::uint64_t FutureStampLimit() {
  const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::system_clock::now().time_since_epoch())
                      .count() +
                  24ll * 3600 * 1000;
  return static_cast<std::uint64_t>(std::max<std::int64_t>(ms, 0)) << facts::kStampLogicalBits;
}

std::optional<Error> ValidateLog(const pb::ProjectArchiveManifest &m, const std::vector<facts::Op> &ops,
                                 const Limits &limits, std::vector<int> &owner) {
  owner.assign(ops.size(), -1);
  if (ops.size() != m.log().count()) return Invalid("log.bin doesn't hold the number of ops its manifest declares");
  std::map<std::uint32_t, int> by_ordinal;
  std::map<facts::SpaceId, int> by_space;
  std::map<std::string, int> by_id;
  for (int i = 0; i < m.programs_size(); ++i) {
    by_ordinal[m.programs(i).ordinal()] = i;
    by_space[RamSpace(m.programs(i).ordinal())] = i;
    by_id[m.programs(i).program_id()] = i;
  }
  std::unordered_map<facts::OpId, std::size_t, facts::OpIdHash> index;
  std::vector<bool> has_record(static_cast<std::size_t>(m.programs_size()), false);
  std::set<std::string> type_archive_names;
  constexpr std::size_t kMaxTypeArchives = 256;
  auto bad = [&](std::size_t i, const std::string &why) {
    return Invalid("log.bin op " + std::to_string(i) + ": " + why);
  };
  for (std::size_t i = 0; i < ops.size(); ++i) {
    const facts::Op &op = ops[i];
    if (!op.id) return bad(i, "it has no id");
    if (!index.emplace(op.id, i).second) return bad(i, "its id repeats an earlier op's");
    if (op.kind != facts::OpKind::Assert && op.kind != facts::OpKind::Retract) return bad(i, "unknown op kind");
    if (!ValidKey(op.key)) return bad(i, "unknown fact kind or an over-long sub");
    if (op.meta.size() > limits.max_value_bytes) return bad(i, "its metadata is over the size limit");
    if (limits.max_stamp && op.stamp > limits.max_stamp)
      return bad(i, "it is stamped more than a day past this daemon's clock (the archive's daemon's clock was "
                    "wrong, or the stamp was made up)");
    if (op.prov.id.size() > kMaxShortText || op.prov.version.size() > kMaxShortText)
      return bad(i, "its provenance is too long");
    // Which program the key belongs to.
    int prog = -1;
    const facts::FactKey &k = op.key;
    // Project-wide types and type archive settings: the project's own, kept
    // whichever programs are imported (owner -2).
    const bool project_types =
        k.addr.space == kProjectSpace &&
        ((k.kind == facts::FactKind::TypeDef && k.addr.offset == kProjectTypesAddress) ||
         (k.kind == facts::FactKind::Note && k.addr.offset == kTypeArchiveAddress &&
          k.sub.starts_with(kTypeArchiveSubPrefix)));
    if (project_types) {
      prog = -2;
    } else if (k.addr.space == kProjectSpace) {
      if (k.kind != facts::FactKind::Note) return bad(i, "a project record that isn't a note");
      if (k.sub == kProgramRecordSub || k.sub == kProgramNameSub || k.sub == kProgramDeletedSub) {
        auto it = by_ordinal.find(static_cast<std::uint32_t>(std::min<std::uint64_t>(k.addr.offset, UINT32_MAX)));
        if (k.addr.offset >= kMaxOrdinals || it == by_ordinal.end()) return bad(i, "a record of no program in the archive");
        prog = it->second;
      } else if (k.sub == kDiffSessionSubName) {
        prog = -1;  // checked with its value below
      } else {
        return bad(i, "a project record of an unknown kind (" + k.sub.substr(0, 64) + ")");
      }
    } else {
      auto it = by_space.find(k.addr.space);
      if (it == by_space.end()) return bad(i, "a key in no program's space");
      prog = it->second;
    }
    owner[i] = prog;
    if (op.kind == facts::OpKind::Retract) {
      auto t = index.find(op.target_id);
      if (!op.target_id || t == index.end() || t->second >= i) return bad(i, "it retracts no earlier op of the archive");
      if (!(ops[t->second].key == op.key)) return bad(i, "it retracts an op on another key");
      if (op.depends_on_id) return bad(i, "a retraction with a dependency");
      if (!std::holds_alternative<std::monostate>(op.value)) return bad(i, "a retraction with a value");
      if (k.addr.space == kProjectSpace && k.sub == kDiffSessionSubName) owner[i] = owner[t->second];
      continue;
    }
    if (op.depends_on_id) {
      auto t = index.find(op.depends_on_id);
      if (t == index.end() || t->second >= i) return bad(i, "it depends on no earlier op of the archive");
    }
    // The value, by kind.
    const facts::FactValue &v = op.value;
    const auto *text = std::get_if<std::string>(&v);
    if (text && text->size() > limits.max_value_bytes) return bad(i, "its value is over the size limit");
    const bool none = std::holds_alternative<std::monostate>(v);
    try {
      if (project_types) {
        if (!none && !text) return bad(i, "a project type or archive setting that isn't text");
        if (k.kind == facts::FactKind::TypeDef && text && !text->empty() && k.sub.find(':') == std::string::npos)
          (void)DecodeTypeRecord(*text);
        if (k.kind == facts::FactKind::Note) {
          // A type archive attached to the project: what SetTypeArchive
          // (AppendAssertions' type_archive) would have accepted, each
          // header parsed at every program's load.
          const std::string name = k.sub.substr(kTypeArchiveSubPrefix.size());
          if (name.empty() || name.size() > 64 || cparse::archive_stem(name) != name)
            return bad(i, "a type archive setting with a name that isn't valid");
          type_archive_names.insert(name);
          if (type_archive_names.size() > kMaxTypeArchives)
            return bad(i, "more than " + std::to_string(kMaxTypeArchives) + " type archives");
          if (text && !text->empty()) {
            pb::TypeArchiveSetting a;
            if (!a.ParseFromString(*text)) return bad(i, "a type archive setting that can't be decoded");
            if (a.header().size() > (32u << 20) || a.sidecar().size() > (64u << 20))
              return bad(i, "a type archive setting over the size limits");
            std::string err;
            if (!a.sidecar().empty() && !ReadTypeArchiveSidecar(a.sidecar(), &err))
              return bad(i, "a type archive setting's sidecar: " + err);
          }
        }
        continue;
      }
      if (k.addr.space == kProjectSpace) {
        if (!text) return bad(i, "a project record that isn't text");
        if (k.sub == kProgramRecordSub) {
          const ProgramSource src = facts::decode_from_string<ProgramSource>(*text);
          const pb::ArchiveProgram &p = m.programs(prog);
          if (src.sha256 != p.sha256() || src.file_size != p.size() || src.ordinal != p.ordinal() ||
              src.ram_space != RamSpace(p.ordinal()) || src.file_space != FileSpace(p.ordinal()))
            return bad(i, "program " + p.key() + "'s record doesn't match its manifest entry");
          if (src.loader.size() > kMaxShortText || src.language_id.size() > kMaxShortText ||
              src.compiler_spec_id.size() > kMaxShortText)
            return bad(i, "program " + p.key() + "'s record has an over-long field");
          has_record[static_cast<std::size_t>(prog)] = true;
        } else if (k.sub == kProgramNameSub) {
          if (!text->empty() && !ValidName(*text)) return bad(i, "a program name that isn't valid");
        } else if (k.sub == kDiffSessionSubName) {
          const DiffSessionRecord s = facts::decode_from_string<DiffSessionRecord>(*text);
          auto a = by_id.find(s.program_a), b = by_id.find(s.program_b);
          if (a == by_id.end() || b == by_id.end() || a->second == b->second)
            return bad(i, "a diff session between programs not in the archive");
          if (DiffSessionAddress(s.id) != k.addr.offset || s.id.empty() || s.id.size() > 64 ||
              s.id.find('/') != std::string::npos)
            return bad(i, "a diff session record at the wrong key");
          // Belongs to both; RewriteLog keeps it when both are imported.
          owner[i] = -1;
        }
        continue;
      }
      switch (k.kind) {
        case facts::FactKind::Name:
        case facts::FactKind::Type:
        case facts::FactKind::Comment:
        case facts::FactKind::Note:
        case facts::FactKind::Match:
          if (!none && !text) return bad(i, "a value that isn't text");
          // Data settings (SetDataSettings): what the API would write.
          if (k.kind == facts::FactKind::Note && IsDataSettingsTag(k.sub)) {
            if (k.sub.size() > kDataTypeSettingsPrefix.size() + kMaxDataSettingsName)
              return bad(i, "data settings for an over-long field or type name");
            if (text && !text->empty() && !DataSettings::parse(*text))
              return bad(i, "data settings that can't be read");
          }
          break;
        case facts::FactKind::TypeDef:
          if (!none && !text) return bad(i, "a type that isn't text");
          // A record keyed by its hash; "name:" bindings, "category:" paths
          // and any later prefixed sub hold text.
          if (text && !text->empty() && k.sub.find(':') == std::string::npos) (void)DecodeTypeRecord(*text);
          break;
        case facts::FactKind::FunctionBounds:
          if (const auto *set = std::get_if<facts::AddressSet>(&v)) {
            for (const auto &r : set->ranges())
              if (r.first.space != k.addr.space || r.last.space != k.addr.space || r.first.offset > r.last.offset)
                return bad(i, "a function body outside its program's space");
          } else if (!none && !std::holds_alternative<std::int64_t>(v)) {
            return bad(i, "a function body that isn't an address set");
          }
          break;
        case facts::FactKind::FlowOverride:
          if (!none && !std::holds_alternative<std::int64_t>(v)) return bad(i, "a flow override that isn't a number");
          break;
        case facts::FactKind::Patch:
          if (!none && (!text || text->size() > facts::kMaxPatchBytes)) return bad(i, "a patch that isn't bytes or is too long");
          break;
        case facts::FactKind::MemoryRegion:
          if (!none && !text) return bad(i, "a memory-map edit that isn't text");
          if (text && !text->empty()) {
            if (k.sub.starts_with(analysis::kBlockSubPrefix)) {
              if (!analysis::decode_block_edit(*text)) return bad(i, "a block edit that can't be decoded");
            } else if (k.sub.starts_with(analysis::kRegionSubPrefix)) {
              auto r = analysis::decode_region(*text);
              if (!r) return bad(i, "a region that can't be decoded");
              // Its bytes are in the program's file space: where the
              // archive's region file goes, or missing (as a region a
              // peer added reads until its bytes arrive).
              if (r->bytes && r->bytes->space != FileSpace(m.programs(prog).ordinal()))
                return bad(i, "a region whose bytes are outside its program's file space");
            } else {
              return bad(i, "a memory-map edit of an unknown kind");
            }
          }
          break;
        case facts::FactKind::CodeUnit:
          if (!none && !text) return bad(i, "a listing edit that isn't text");
          if (text && !text->empty()) (void)facts::decode_from_string<analysis::UnitMark>(*text);
          break;
        case facts::FactKind::Mutability:
          if (!none && !text) return bad(i, "a mutability edit that isn't text");
          if (text && !text->empty()) (void)facts::decode_from_string<analysis::MutabilityMark>(*text);
          break;
        case facts::FactKind::Equate:
          if (!none && !text) return bad(i, "an operand display that isn't text");
          if (text && !text->empty() && !analysis::parse_operand_display(*text)) return bad(i, "an operand display that can't be read");
          break;
        case facts::FactKind::Reference:
          if (!none && !text) return bad(i, "a reference that isn't text");
          if (text && !text->empty() && !analysis::parse_user_ref(k.sub, *text)) return bad(i, "a reference that can't be read");
          break;
        case facts::FactKind::CallSignature:
          if (!none && !text) return bad(i, "a call signature that isn't text");
          if (text && !text->empty() && (!text->starts_with("h:") || text->size() < 3))
            return bad(i, "a call signature that isn't a type hash");
          break;
        case facts::FactKind::NoReturn:
          if (!none && !std::holds_alternative<std::int64_t>(v)) return bad(i, "a no-return mark that isn't a number");
          break;
        case facts::FactKind::Fallthrough:
          // An address in the program's space, or a number (none, default).
          if (const auto *to = std::get_if<facts::Address>(&v)) {
            if (to->space != k.addr.space) return bad(i, "a fallthrough outside its program's space");
            break;
          }
          if (!none && !std::holds_alternative<std::int64_t>(v)) return bad(i, "a fallthrough that isn't an address or a number");
          break;
        case facts::FactKind::RegisterValue:
          if (!none && !text) return bad(i, "a register value that isn't text");
          if (!analysis::parse_register_value_sub(k.sub)) return bad(i, "a register value key that can't be read");
          if (text && !text->empty() && !analysis::parse_register_value_text(*text)) return bad(i, "a register value that can't be read");
          break;
        case facts::FactKind::Language:
          if (!none && !text) return bad(i, "a language that isn't text");
          if (k.addr.offset != 0 || !k.sub.empty()) return bad(i, "a language key that isn't the program's");
          if (text && text->size() > 256) return bad(i, "a language that's too long");
          break;
        case facts::FactKind::Rebase:
          if (!none && !text) return bad(i, "an image base that isn't text");
          if (k.addr.offset != 0 || !k.sub.empty()) return bad(i, "an image base key that isn't the program's");
          if (text && !text->empty() && !facts::Shift::parse(*text)) return bad(i, "an image base that can't be read");
          break;
      }
      if (std::holds_alternative<facts::Address>(v) && k.kind != facts::FactKind::Fallthrough)
        return bad(i, "an address value no kind uses");
    } catch (const std::exception &e) {
      return bad(i, std::string("its value can't be decoded: ") + e.what());
    }
  }
  for (int i = 0; i < m.programs_size(); ++i)
    if (!has_record[static_cast<std::size_t>(i)]) return Invalid("program " + m.programs(i).key() + " has no record in log.bin");
  return std::nullopt;
}

Rewritten RewriteLog(const pb::ProjectArchiveManifest &m, const std::vector<facts::Op> &ops,
                     const std::vector<int> &owner, const std::vector<ProgramPlan> &plans,
                     const std::function<facts::ReplicaId()> &new_replica) {
  Rewritten out;
  out.sources.resize(plans.size());
  std::map<facts::SpaceId, facts::SpaceId> ram, file;
  std::map<std::uint32_t, std::uint32_t> ordinal;
  std::map<std::string, std::string> program_id;
  for (std::size_t i = 0; i < plans.size(); ++i) {
    if (!plans[i].include) continue;
    const std::uint32_t o = m.programs(static_cast<int>(i)).ordinal();
    ram[RamSpace(o)] = RamSpace(plans[i].ordinal);
    file[FileSpace(o)] = FileSpace(plans[i].ordinal);
    ordinal[o] = plans[i].ordinal;
    program_id[m.programs(static_cast<int>(i)).program_id()] = plans[i].id;
  }
  // Diff sessions between two imported programs, under new ids.
  std::map<std::string, std::string> session;
  std::map<std::uint64_t, std::string> session_at;  // old record address -> old id
  for (const facts::Op &op : ops) {
    if (op.kind != facts::OpKind::Assert || op.key.addr.space != kProjectSpace || op.key.sub != kDiffSessionSubName)
      continue;
    const auto rec = facts::decode_from_string<DiffSessionRecord>(std::get<std::string>(op.value));
    if (session.contains(rec.id) || !program_id.contains(rec.program_a) || !program_id.contains(rec.program_b)) continue;
    session[rec.id] = NewDiffSessionId(program_id[rec.program_a], program_id[rec.program_b], new_replica(),
                                       session.size() + 1, op.time_ns);
    session_at[op.key.addr.offset] = rec.id;
  }
  std::map<facts::ReplicaId, facts::ReplicaId> replica;
  std::map<facts::ReplicaId, std::uint64_t> counter;
  std::unordered_map<facts::OpId, facts::OpId, facts::OpIdHash> ids;
  auto remap_space = [&](facts::SpaceId s) {
    auto it = ram.find(s);
    return it == ram.end() ? s : it->second;
  };
  for (std::size_t i = 0; i < ops.size(); ++i) {
    facts::Op op = ops[i];
    facts::FactKey &k = op.key;
    // Keep it?
    if (k.addr.space == kProjectSpace && k.sub == kDiffSessionSubName) {
      auto s = session_at.find(k.addr.offset);
      if (s == session_at.end()) continue;
      k.addr.offset = DiffSessionAddress(session.at(s->second));
    } else if (owner[i] == -2) {
      // The project's types and archive settings: kept as they are.
    } else {
      if (owner[i] < 0 || !plans[static_cast<std::size_t>(owner[i])].include) continue;
      if (k.kind == facts::FactKind::Match) {
        const std::string sid = k.sub.substr(0, k.sub.find('/'));
        auto s = session.find(sid);
        if (s == session.end()) continue;
        k.sub = s->second + k.sub.substr(sid.size());
      }
      if (k.addr.space == kProjectSpace) k.addr.offset = ordinal.at(static_cast<std::uint32_t>(k.addr.offset));
      else k.addr.space = remap_space(k.addr.space);
    }
    // Ids under fresh replicas, counters dense in archive order.
    auto r = replica.find(op.id.replica);
    if (r == replica.end()) {
      facts::ReplicaId fresh = 0;
      do fresh = new_replica();
      while (fresh == 0 || std::any_of(replica.begin(), replica.end(), [&](const auto &e) { return e.second == fresh; }));
      r = replica.emplace(op.id.replica, fresh).first;
    }
    const facts::OpId old = op.id;
    op.id = facts::OpId{r->second, ++counter[r->second]};
    ids[old] = op.id;
    auto map_id = [&](facts::OpId id) {
      auto it = ids.find(id);
      return it == ids.end() ? facts::OpId{} : it->second;
    };
    op.target_id = map_id(op.target_id);
    op.depends_on_id = map_id(op.depends_on_id);
    op.supersedes = map_id(op.supersedes);
    op.seq = op.target = op.depends_on = 0;
    if (op.kind == facts::OpKind::Retract && !op.target_id) continue;  // can't happen: same key, same owner
    // Values.
    if (auto *set = std::get_if<facts::AddressSet>(&op.value)) {
      facts::AddressSet moved;
      for (facts::AddressRange rg : set->ranges()) {
        rg.first.space = remap_space(rg.first.space);
        rg.last.space = remap_space(rg.last.space);
        moved.add(rg);
      }
      op.value = std::move(moved);
    } else if (auto *to = std::get_if<facts::Address>(&op.value)) {
      to->space = remap_space(to->space);
    } else if (auto *text = std::get_if<std::string>(&op.value); text && op.kind == facts::OpKind::Assert) {
      if (k.addr.space == kProjectSpace && k.sub == kProgramRecordSub) {
        ProgramSource src = facts::decode_from_string<ProgramSource>(*text);
        const std::size_t p = static_cast<std::size_t>(owner[i]);
        src.id = plans[p].id;
        src.name = plans[p].name;
        src.ordinal = plans[p].ordinal;
        src.ram_space = RamSpace(src.ordinal);
        src.file_space = FileSpace(src.ordinal);
        src.path.clear();  // a path on the exporter's host means nothing here
        *text = facts::encode_to_string(src);
        out.sources[p] = std::move(src);
      } else if (k.addr.space == kProjectSpace && k.sub == kDiffSessionSubName) {
        DiffSessionRecord rec = facts::decode_from_string<DiffSessionRecord>(*text);
        rec.id = session.at(rec.id);
        rec.program_a = program_id.at(rec.program_a);
        rec.program_b = program_id.at(rec.program_b);
        *text = facts::encode_to_string(rec);
      } else if (k.kind == facts::FactKind::MemoryRegion && k.sub.starts_with(analysis::kRegionSubPrefix) &&
                 !text->empty()) {
        auto rg = analysis::decode_region(*text);
        if (rg && rg->bytes) {
          auto f = file.find(rg->bytes->space);
          if (f != file.end()) rg->bytes->space = f->second;
          *text = analysis::encode_region(*rg);
        }
      }
    }
    // The API's metadata: diff session and program ids it names.
    if (!op.meta.empty()) {
      pb::Assertion meta;
      if (meta.ParseFromString(op.meta)) {
        bool changed = false;
        if (meta.body().has_diff_match()) {
          auto s = session.find(meta.body().diff_match().session_id());
          if (s != session.end()) {
            meta.mutable_body()->mutable_diff_match()->set_session_id(s->second);
            changed = true;
          }
        }
        if (meta.has_ported_from()) {
          auto *pf = meta.mutable_ported_from();
          if (auto s = session.find(pf->session_id()); s != session.end()) pf->set_session_id(s->second), changed = true;
          if (auto p = program_id.find(pf->program_id()); p != program_id.end()) pf->set_program_id(p->second), changed = true;
        }
        if (changed) op.meta = Deterministic(meta);
      }
    }
    out.ops.push_back(std::move(op));
  }
  return out;
}

}  // namespace revkit::backend::archive
