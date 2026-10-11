// Project archives (docs/backend.md, "Project archives"): a project, some
// of its programs or a folder as one .rkproj file, and reading one back.
//
// The container is a gzip-compressed POSIX tar whose first member is
// manifest.json (a revkit.v1.ProjectArchiveManifest as protobuf JSON); the
// others are log.bin (the fact log's ops) and, per program,
// programs/<key>/program.bin and programs/<key>/regions/<sha256>.bin. An
// archive is untrusted input: the reader takes only the members the
// manifest declares, at the sizes and SHA-256s it declares, never names a
// file after anything in the archive, and stops decompressing once it has
// read what the manifest declared (a decompression bomb gets no further
// than its own manifest's sizes, which the limits bound). The op log is
// decoded and checked op by op (ValidateLog) before any of it reaches a
// project, and rewritten (RewriteLog) into the target project's program
// ids, fact spaces and fresh replicas, so the ops merge as if a new peer
// had made them, with their provenance, stamps and history.
//
// Everything here is pure (no backend state) so it can be fuzzed
// (fuzz/project_archive_fuzzer.cc).
#pragma once

#include "model.h"
#include "revkit/facts/fact.h"
#include "revkit/v1/project.pb.h"

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::backend::archive {

namespace pb = ::revkit::v1;

inline constexpr std::string_view kFormat = "revkit-project-archive";
inline constexpr std::uint32_t kFormatVersion = 1;
// The op encoding in log.bin: facts::Op's codec, as SyncService sends it.
inline constexpr std::uint32_t kOpFormat = 1;
inline constexpr std::string_view kManifestPath = "manifest.json";
inline constexpr std::string_view kLogPath = "log.bin";
inline constexpr std::string_view kFileExtension = ".rkproj";

// The project's fact-store layout (image_backend.cc): project records in
// space 15; program k's keys in 16 + 2k, its file's bytes in 17 + 2k; its
// record, display name, deletion and folder are NOTE keys in the project
// space at its ordinal; folders are NOTE keys at kFolderAddress.
inline constexpr facts::SpaceId kProjectSpace = 15;
inline constexpr facts::SpaceId kFirstProgramSpace = 16;
inline constexpr std::uint32_t kMaxOrdinals = 16384;
inline constexpr std::string_view kProgramRecordSub = "program";
inline constexpr std::string_view kProgramNameSub = "revkit:program.name";
inline constexpr std::string_view kProgramDeletedSub = "revkit:program.deleted";
inline constexpr std::string_view kProgramFolderSub = "revkit:program.folder";
inline constexpr std::string_view kFolderSubPrefix = "revkit:folder:";
inline constexpr std::uint64_t kFolderAddress = std::uint64_t{1} << 48;  // above ordinals and diff-session hashes
inline constexpr std::string_view kDiffSessionSubName = "diff-session";
// Project-wide types (docs/types.md#project-types): TYPE_DEF keys in the
// project space at address 0, as a program's are in its own space.
inline constexpr std::uint64_t kProjectTypesAddress = 0;
// Type archives attached to the project, and the shipped ones turned off or
// on (AssertionBody.type_archive): NOTE keys at this address, sub
// "revkit:type-archive:<name>".
inline constexpr std::uint64_t kTypeArchiveAddress = (std::uint64_t{1} << 48) + 1;
inline constexpr std::string_view kTypeArchiveSubPrefix = "revkit:type-archive:";

inline facts::SpaceId RamSpace(std::uint32_t ordinal) {
  return static_cast<facts::SpaceId>(kFirstProgramSpace + 2 * ordinal);
}
inline facts::SpaceId FileSpace(std::uint32_t ordinal) { return static_cast<facts::SpaceId>(RamSpace(ordinal) + 1); }

// What the reader accepts. Defaults suit a daemon; tests and the fuzzer
// lower them.
struct Limits {
  std::uint64_t max_manifest_bytes = 16ull << 20;
  std::uint64_t max_program_bytes = 4ull << 30;  // as a peer's program file
  std::uint64_t max_region_bytes = 4ull << 30;
  std::uint64_t max_log_bytes = 8ull << 30;
  // Every member the manifest declares, together: what the reader will
  // decompress at most.
  std::uint64_t max_total_bytes = 32ull << 30;
  std::uint32_t max_programs = 4096;
  std::uint32_t max_regions = 4096;  // per program
  std::uint32_t max_folders = 65536;
  std::uint64_t max_ops = 200'000'000;
  std::uint64_t max_op_bytes = 64ull << 20;
  std::uint64_t max_value_bytes = 16ull << 20;
};

// Why an archive was refused. `unsupported`: a format or version this
// daemon doesn't read (FAILED_PRECONDITION); otherwise it is malformed or
// over a limit (INVALID_ARGUMENT).
struct Error {
  std::string message;
  bool unsupported = false;
};

// --- Writing ----------------------------------------------------------------

// Writes a .rkproj stream: members in order, each declared with its size
// first. `sink` receives compressed bytes and returns false to stop (the
// client went away); every call then returns false.
class Writer {
 public:
  using Sink = std::function<bool(std::string_view)>;
  explicit Writer(Sink sink, int level = 6);
  ~Writer();
  Writer(const Writer &) = delete;
  Writer &operator=(const Writer &) = delete;

  bool begin_file(std::string_view path, std::uint64_t size);
  bool write(std::string_view data);
  bool end_file();
  bool add_file(std::string_view path, std::string_view data) {
    return begin_file(path, data.size()) && write(data) && end_file();
  }
  // The end-of-archive blocks and the gzip trailer.
  bool finish();
  std::uint64_t compressed_bytes() const { return out_bytes_; }

 private:
  bool deflate_out(std::string_view in, int flush);
  struct Z;
  std::unique_ptr<Z> z_;
  Sink sink_;
  bool ok_ = true;
  std::uint64_t remaining_ = 0, written_ = 0, out_bytes_ = 0;
  bool in_file_ = false;
};

// log.bin: "RKLOG1\n", then each op as its varint length and encoding.
std::string LogHeader();
void AppendLogOp(std::string &out, const facts::Op &op);

// The manifest as written into the archive (protobuf JSON, sorted fields).
std::string ManifestJson(const pb::ProjectArchiveManifest &m);

// --- Reading ----------------------------------------------------------------

// Reads compressed bytes into buf; returns how many (0 at the end).
using Source = std::function<std::size_t(char *buf, std::size_t n)>;

// Which declared member an entry is.
struct Member {
  enum Kind { kLog, kProgram, kRegion } kind = kLog;
  int program = -1;  // index in manifest.programs
  int region = -1;   // index in that program's regions
  std::uint64_t size = 0;
};

// Receives each member's bytes once the manifest has been read and
// checked. Members arrive in archive order; each is begun, fed, ended
// (and its size and SHA-256 checked before end() is called with ok =
// true; a mismatch ends the read with an error after end(ok = false)).
class MemberSink {
 public:
  virtual ~MemberSink() = default;
  virtual void begin(const Member &m) = 0;
  virtual void data(std::string_view bytes) = 0;
  virtual void end(bool ok) = 0;
};

// Checks a manifest on its own: format and versions, keys, names, paths,
// hashes, sizes and counts against the limits.
std::optional<Error> ValidateManifest(const pb::ProjectArchiveManifest &m, const Limits &limits);

// Reads an archive: the manifest (checked), then every member it declares,
// exactly once each, at its declared size and SHA-256. Anything else in the
// archive (other names, links, devices, duplicates, trailing data past the
// declared members) is refused.
std::optional<Error> ReadArchive(const Source &source, const Limits &limits, pb::ProjectArchiveManifest &manifest,
                                 MemberSink &sink);

// Decodes log.bin (its whole contents) into ops, in file order.
std::optional<Error> DecodeLog(std::string_view data, const Limits &limits, std::vector<facts::Op> &out);

// --- The ops ----------------------------------------------------------------

// Checks every op against the manifest: ids unique and references to
// earlier ops only (a retraction's target on the same key), keys only in
// the archive's programs' spaces or their project records, and values of
// the type each kind has, the encoded ones (program records, memory-map
// edits, listing edits, types, diff sessions) decodable and consistent
// with the manifest. Returns the archive program each op belongs to
// (index in manifest.programs) in `owner`.
std::optional<Error> ValidateLog(const pb::ProjectArchiveManifest &m, const std::vector<facts::Op> &ops,
                                 const Limits &limits, std::vector<int> &owner);

// Where an archive program goes in the target project.
struct ProgramPlan {
  bool include = false;
  std::string id;    // the new program id
  std::string name;  // its record's name (the id's last part)
  std::uint32_t ordinal = 0;
};

struct Rewritten {
  std::vector<facts::Op> ops;  // in a causal order, ids under fresh replicas
  // Per manifest program: its new record (ProgramSource) as staged.
  std::vector<std::optional<ProgramSource>> sources;
};

// Rewrites validated ops for the target: only included programs' ops
// (and diff sessions between two included programs); spaces, ordinals,
// program ids and session ids remapped; each source replica replaced by
// a fresh one from `new_replica` with dense counters, references by id
// remapped. Provenance, stamps, times and metadata stay.
Rewritten RewriteLog(const pb::ProjectArchiveManifest &m, const std::vector<facts::Op> &ops,
                     const std::vector<int> &owner, const std::vector<ProgramPlan> &plans,
                     const std::function<facts::ReplicaId()> &new_replica);

// Folder paths: "/" or "/a/b" with valid names (no empty, ".", "..").
bool ValidFolderPath(std::string_view path);
// A program or folder name: 1..200 characters, no "/" or control characters.
bool ValidName(std::string_view name);

}  // namespace revkit::backend::archive
