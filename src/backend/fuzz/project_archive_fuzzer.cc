// libFuzzer target for project archives (.rkproj, docs/backend.md "Project
// archives"): the input is an archive as ImportProjectArchive receives it.
// It runs everything the import does before touching a project: the gzip
// stream, the tar headers, the manifest (protobuf JSON) and its checks, every
// member's size and hash, log.bin's ops and their validation, and the
// rewrite into a target's ids and spaces. Limits are small so a run stays
// fast; the decompression-bomb guard is what keeps it from inflating more
// than the manifest declares.
#include "project_archive.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace {

namespace archive = revkit::backend::archive;

struct Sink final : archive::MemberSink {
  std::string log;
  bool in_log = false;
  void begin(const archive::Member &m) override {
    in_log = m.kind == archive::Member::kLog;
    if (in_log) log.clear();
  }
  void data(std::string_view b) override {
    if (in_log) log.append(b);
  }
  void end(bool) override {}
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  archive::Limits limits;
  limits.max_manifest_bytes = 1 << 20;
  limits.max_program_bytes = 4 << 20;
  limits.max_region_bytes = 1 << 20;
  limits.max_log_bytes = 8 << 20;
  limits.max_total_bytes = 16 << 20;
  limits.max_programs = 64;
  limits.max_regions = 16;
  limits.max_folders = 256;
  limits.max_ops = 100000;
  limits.max_op_bytes = 1 << 20;
  limits.max_value_bytes = 1 << 20;

  std::size_t at = 0;
  archive::Source source = [&](char *buf, std::size_t n) {
    const std::size_t take = std::min(n, size - at);
    std::memcpy(buf, data + at, take);
    at += take;
    return take;
  };
  revkit::v1::ProjectArchiveManifest manifest;
  Sink sink;
  if (archive::ReadArchive(source, limits, manifest, sink)) return 0;
  std::vector<revkit::facts::Op> ops;
  if (archive::DecodeLog(sink.log, limits, ops)) return 0;
  std::vector<int> owner;
  if (archive::ValidateLog(manifest, ops, limits, owner)) return 0;
  std::vector<archive::ProgramPlan> plans(static_cast<std::size_t>(manifest.programs_size()));
  for (std::size_t i = 0; i < plans.size(); ++i) {
    plans[i].include = i % 2 == 0;  // a selection, as skip_missing leaves
    plans[i].id = "fuzz/p" + std::to_string(i);
    plans[i].name = "p" + std::to_string(i);
    plans[i].ordinal = static_cast<std::uint32_t>(100 + i);
  }
  std::uint64_t replica = 1;
  archive::RewriteLog(manifest, ops, owner, plans, [&] { return replica++; });
  return 0;
}
